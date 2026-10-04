"""DKIM (RFC 6376): verify every DKIM-Signature on the raw message.

The body is needed for the body hash, so this is the one place the message body is
used. It is never stored.
"""
import base64
import binascii
import logging
import re

import dkim
import dkim.crypto
import dkim.util

from .dnsutil import DnsError

MAX_SIGNATURES = 5  # more are listed as not checked: each one can mean a slow DNS lookup
# Bounds on the work one signature can cause, far above anything real (a signature lists ~10-40 header
# names, a message has a few dozen fields, keys are 1024-4096 bits): dkimpy searches the header block once
# per listed name, and a published key's size and exponent decide the cost of its maths
MAX_SIGNED_HEADERS = 64
MAX_HEADER_FIELDS = 1000
MAX_KEY_BITS = 8192
MAX_KEY_EXPONENT = 2 ** 32
MAX_SIGNATURE_CHARS = 2 * MAX_KEY_BITS // 8  # b= in base64: a signature is as long as its key (~1.4x)

EXPLANATIONS = {
    "pass": "The signature is valid: what {d} signed hasn't changed since it was signed.",
    "fail": "The signature doesn't match. The message was changed after signing, or it was signed "
            "with a different key from the one published for {d}.",
    "permerror": "The signature couldn't be checked: the key for {d} is missing or invalid, or the "
                 "signature header is malformed.",
    "temperror": "A temporary DNS error stopped the check.",
}
# a signature past its x= expiry fails before the key is even fetched, so "doesn't match" would be wrong
# RFC 8301: receivers must not treat an rsa-sha1 signature as valid, whatever the maths says
SHA1 = ("The signature uses rsa-sha1, which receivers no longer accept (RFC 8301), so it counts for "
        "nothing: {d} needs to sign with rsa-sha256.")
EXPIRED = "The signature has expired: {d} set an expiry time (x=) that had passed when the message was checked."
# dkimpy doesn't enforce these key tags (RFC 6376 §3.6.1), so a signature they rule out would otherwise pass
RESTRICTED = ("The key published for {d} doesn't allow this signature (its h= or t= tag), so it counts for "
              "nothing.")


class _Collector(logging.Handler):
    """dkimpy logs the reason for a failure instead of returning it."""

    def __init__(self):
        super().__init__(logging.ERROR)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _dnsfunc(resolver, fetched=None):
    """dkimpy's key lookup through our resolver; the record it returns is also kept in fetched["record"]."""
    def lookup(name, timeout=5):
        name = name.decode() if isinstance(name, bytes) else name
        try:
            records = resolver.txt(name.rstrip("."))
        except DnsError as e:
            raise dkim.DnsTimeoutError(str(e)) from e
        if not records:
            return None
        _check_key_size(records[0])
        if fetched is not None:
            fetched["record"] = records[0]
        return records[0].encode()
    return lookup


def _key_restriction(record, sig_tags, domain):
    """Why the key's own tags rule this signature out, or None: h= (the hash algorithms the key may be
    used with) and t=s (the i= identity must be at d= itself, not a subdomain)."""
    try:  # tag names are case-sensitive (RFC 6376 §3.2): "H=" isn't "h=", so no case folding here
        key = {k.decode(): v.decode() for k, v in dkim.util.parse_tag_value(record.encode()).items()}
    except Exception:  # unparsable here, though dkimpy accepted it: nothing more to enforce
        return None
    algorithm = sig_tags.get("a", "").lower().rpartition("-")[2]
    if "h" in key:  # present but empty (h= or h=:) allows nothing
        hashes = [h.strip().lower() for h in key["h"].split(":") if h.strip()]
        if algorithm not in hashes:
            return f"the key only allows h={':'.join(hashes) or '(nothing)'}, not {algorithm}"
    flags = [f.strip().lower() for f in key.get("t", "").split(":")]
    identity = sig_tags.get("i", "").rpartition("@")[2].lower()
    if "s" in flags and identity and identity != domain:
        return f"the key's t=s flag needs the i= identity to be at {domain} itself, not {identity}"
    return None


def _check_key_size(record):
    """Refuse an RSA key too big to check cheaply (KeyFormatError: the signature becomes a permerror).
    Anything else wrong with the record is left for dkimpy to report."""
    try:
        tags = dkim.util.parse_tag_value(record.encode())
        if tags.get(b"k", b"rsa").strip().lower() != b"rsa" or not tags.get(b"p"):
            return
        der = base64.b64decode(re.sub(rb"\s+", b"", tags[b"p"]))
    except (dkim.util.InvalidTagValueList, binascii.Error, ValueError):
        return
    if len(der) > MAX_KEY_BITS // 8 + 512:  # the key plus its encoding, generously
        raise dkim.KeyFormatError(f"the key is over {MAX_KEY_BITS} bits, too large to check")
    try:
        key = dkim.crypto.parse_public_key(der)
    except Exception:  # unparsable: dkimpy reports it properly
        return
    if key["modulus"].bit_length() > MAX_KEY_BITS or key["publicExponent"] > MAX_KEY_EXPONENT:
        raise dkim.KeyFormatError(f"the key is over {MAX_KEY_BITS} bits or has an oversized exponent, "
                                  "too large to check")


def _friendly(reason):
    """dkimpy's messages include raw bytes; keep the gist."""
    if reason.startswith("body hash mismatch"):
        return "body hash mismatch: the body was changed after it was signed"
    if reason.startswith("missing public key"):
        return "missing public key: no DKIM key is published at that selector"
    if reason.startswith("x= value is past"):
        return "signature expired: its x= time has passed"
    return reason


def _tags(value):
    """Tag=value pairs from a DKIM-style header, whitespace removed."""
    tags = {}
    for part in value.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    return tags


def verify_all(raw, resolver):
    collector = _Collector()
    logger = logging.getLogger("healthcheck.dkim")
    logger.propagate = False
    logger.addHandler(collector)
    try:
        d = dkim.DKIM(raw, logger=logger, minkey=1024)
        count = sum(1 for name, _ in d.headers if name.lower() == b"dkim-signature")
        return [_verify_one(d, i, resolver, collector) for i in range(min(count, MAX_SIGNATURES))]
    finally:
        logger.removeHandler(collector)


def _verify_one(d, idx, resolver, collector):
    collector.messages.clear()
    sig_value = [v for n, v in d.headers if n.lower() == b"dkim-signature"][idx]
    tags = _tags(sig_value.decode("utf-8", "replace"))
    out = {
        "domain": tags.get("d", "").lower(),
        "selector": tags.get("s", ""),
    }
    slots = tags.get("h", "").split(":")  # every slot, empty ones too: dkimpy counts them all
    try:
        if len(d.headers) > MAX_HEADER_FIELDS:
            raise dkim.ParameterError(f"the message has over {MAX_HEADER_FIELDS} header fields, too many to check")
        if len(slots) > MAX_SIGNED_HEADERS:
            raise dkim.ParameterError(f"the signature lists over {MAX_SIGNED_HEADERS} header fields (h=), "
                                      "too many to check")
        if len(tags.get("b", "")) > MAX_SIGNATURE_CHARS:  # its maths grows with its length, whatever the key
            raise dkim.ParameterError(f"the signature value (b=) is over {MAX_SIGNATURE_CHARS} characters, "
                                      "too long to check")
        if tags.get("a", "").lower() == "rsa-sha1":
            raise dkim.ParameterError("rsa-sha1 is no longer accepted (RFC 8301)")
        fetched = {}
        ok = d.verify(idx=idx, dnsfunc=_dnsfunc(resolver, fetched))
        restriction = ok and _key_restriction(fetched.get("record", ""), tags, out["domain"])
        if restriction:
            result, reason = "fail", restriction
        elif ok:
            result, reason = "pass", ""
        elif collector.messages:
            # only key lookup problems are logged: missing/bad key, or a DNS failure
            reason = collector.messages[-1]
            result = "temperror" if "DnsTimeoutError" in reason else "permerror"
        else:
            result, reason = "fail", "signature did not verify"
    except dkim.ValidationError as e:
        result, reason = "fail", str(e)
    except dkim.KeyFormatError as e:
        result, reason = ("fail" if "too small" in str(e) else "permerror"), str(e)
    except dkim.DKIMException as e:
        result, reason = "permerror", str(e)
    except Exception as e:  # dkimpy's own crash on a malformed tag (e.g. IndexError, ValueError): this
        # signature can't be checked, but the rest of the analysis carries on
        result, reason = "permerror", f"the signature couldn't be checked ({type(e).__name__})"
    explanation = (EXPIRED if reason.startswith("x= value is past") else
                   SHA1 if reason.startswith("rsa-sha1") else
                   RESTRICTED if reason.startswith(("the key only allows", "the key's t=s")) else EXPLANATIONS[result])
    out.update(result=result, reason=_friendly(reason),
               explanation=explanation.format(d=out["domain"] or "the signer"))
    return out
