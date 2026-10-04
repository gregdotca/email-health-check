"""DMARC (RFC 7489): policy lookup and SPF/DKIM alignment against the From: domain."""
import re
from urllib.parse import urlsplit

from publicsuffixlist import PublicSuffixList

from .dnsutil import DnsError

_psl = PublicSuffixList()

POLICY_EFFECT = {
    "none": "The policy is p=none (monitoring only), so receivers are asked not to act on a failure.",
    "quarantine": "The policy is p=quarantine, so receivers that honour DMARC will likely put a "
                  "failing message in spam.",
    "reject": "The policy is p=reject, so receivers that honour DMARC will likely refuse a failing message.",
}


def org_domain(domain):
    return _psl.privatesuffix(domain) or domain


def aligned(auth_domain, from_domain, mode):
    if not auth_domain:
        return False
    auth_domain, from_domain = auth_domain.lower(), from_domain.lower()
    if mode == "s":
        return auth_domain == from_domain
    return org_domain(auth_domain) == org_domain(from_domain)


def _tag_list(text):
    """[(tag, value)] in order; parts without "=" are ignored."""
    pairs = []
    for part in text.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            pairs.append((k.strip().lower(), v.strip()))
    return pairs


DMARC_START = re.compile(r"\s*v\s*=\s*DMARC1\s*(;|$)")
# a reporting URI (RFC 7489 §6.4): scheme:something made of URI characters, where every % starts a
# %HH escape, optionally followed by !size (an unsigned 64-bit number with an optional k/m/g/t unit)
REPORT_URI = re.compile(r"(?P<uri>[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9\-._~:/?#\[\]@$&'()*+;=]|%[0-9A-Fa-f]{2})+)"
                        r"(?:!(?P<size>[0-9]{1,20})(?P<unit>[kmgt])?)?")  # 20 digits: int() stays cheap
UNIT = {None: 1, "k": 2 ** 10, "m": 2 ** 20, "g": 2 ** 30, "t": 2 ** 40}


def valid_report_uri(uri):
    """A syntactically valid reporting URI: allowed characters and escapes (the regex), a structure
    Python's URL parser accepts (e.g. no unclosed "[" in a host), an address in a mailto:, and a
    !size that fits in 64 bits. Never raises."""
    m = REPORT_URI.fullmatch(uri.strip())
    if not m or (m["size"] is not None and int(m["size"]) * UNIT[m["unit"]] >= 2 ** 64):
        return False
    try:
        parts = urlsplit(m["uri"])
    except ValueError:
        return False
    if parts.scheme.lower() == "mailto":
        local, _, domain = parts.path.rpartition("@")
        return bool(local and domain)
    return bool(parts.netloc or parts.path)


def is_dmarc_record(text):
    """RFC 7489: a DMARC record starts with exactly v=DMARC1 (nothing before it); any other TXT
    record is ignored."""
    return bool(DMARC_START.match(text))


def has_valid_rua(tags):
    """At least one syntactically valid reporting URI in rua= (needed for the p=none fallback)."""
    return any(valid_report_uri(uri) for uri in tags.get("rua", "").split(","))


def parse_record(text):
    """(tags, problems). Any problem here (a repeated tag) makes the whole record invalid."""
    tags, problems = {}, []
    for k, v in _tag_list(text):
        if k in tags:
            return tags, [f"the {k}= tag appears more than once"]
        tags[k] = v
    return tags, problems


def find_record(resolver, from_domain):
    """Look at _dmarc.<from domain>, then _dmarc.<organizational domain>.

    Returns (record text, domain it was found at) or None.
    """
    names = [from_domain]
    org = org_domain(from_domain)
    if org != from_domain:
        names.append(org)
    for name in names:
        records = [r for r in resolver.txt("_dmarc." + name) if is_dmarc_record(r)]
        if len(records) > 1:
            raise ValueError(f"_dmarc.{name} has more than one DMARC record, so none of them apply")
        if records:
            return records[0], name
    return None


def check_dmarc(resolver, from_domain, spf, dkim_sigs):
    """spf: result of check_spf (or None); dkim_sigs: results of verify_all."""
    out = {"from_domain": from_domain, "record": None, "record_domain": None, "policy": None,
           "pct": None, "adkim": "r", "aspf": "r", "spf_aligned": False, "dkim_aligned": False,
           "notes": []}
    try:
        found = find_record(resolver, from_domain)
    except DnsError as e:
        return {**out, "result": "temperror", "explanation": f"A temporary DNS error stopped the check: {e}"}
    except ValueError as e:
        return {**out, "result": "permerror", "explanation": str(e)}

    if found:
        text, record_domain = found
        out["record"], out["record_domain"] = text, record_domain
        tags, problems = parse_record(text)
        if problems:
            return {**out, "result": "permerror", "notes": [p[0].upper() + p[1:] + "." for p in problems],
                    "explanation": f"The DMARC record at _dmarc.{record_domain} is invalid ({problems[0]}), "
                                   "so receivers ignore it."}
        notes = out["notes"]
        for tag in ("adkim", "aspf"):
            value = tags.get(tag, "r").lower()
            if value not in ("r", "s"):
                notes.append(f"{tag}={tags[tag]} isn't valid (r or s), so the default r (relaxed) applies.")
                value = "r"
            out[tag] = value
        policy = tags.get("p", "").lower()
        bad = []  # RFC 7489 §6.6.3: a missing/invalid p= or an invalid sp= means the same fallback
        if policy not in POLICY_EFFECT:
            bad.append(f"p={tags['p']} isn't a valid policy" if "p" in tags else "the p= tag is missing")
        if "sp" in tags and tags["sp"].lower() not in POLICY_EFFECT:
            bad.append(f"sp={tags['sp']} isn't a valid policy")
        if bad:
            problem = " and ".join(bad)
            problem = problem[0].upper() + problem[1:] if problem.startswith("the ") else problem
            if not has_valid_rua(tags):
                return {**out, "result": "permerror", "notes": [problem + "."],
                        "explanation": f"The DMARC record at _dmarc.{record_domain} has an invalid policy and no "
                                       "valid rua= reporting address, so receivers ignore it."}
            notes.append(problem + ". Because the record has a valid rua= address, receivers treat it as p=none.")
            policy = "none"
        elif record_domain != from_domain and "sp" in tags:  # the record came from the org domain
            policy = tags["sp"].lower()
        out["policy"] = policy
        pct = tags.get("pct", "100")
        if not (re.fullmatch(r"[0-9]{1,3}", pct) and int(pct) <= 100):  # ASCII digits only: "²" isn't one
            notes.append(f"pct={pct} isn't a number from 0 to 100, so 100 applies.")
            pct = "100"
        out["pct"] = pct

    if spf and spf["result"] == "pass" and aligned(spf["domain"], from_domain, out["aspf"]):
        out["spf_aligned"] = True
    out["dkim_aligned"] = any(s["result"] == "pass" and aligned(s["domain"], from_domain, out["adkim"])
                              for s in dkim_sigs)
    passed = out["spf_aligned"] or out["dkim_aligned"]

    if not found:
        out["result"] = "none"
        out["explanation"] = (f"{from_domain} has no DMARC record, so receivers fall back to their own rules. "
                              + ("SPF or DKIM is aligned anyway, so it would pass." if passed else
                                 "Neither SPF nor DKIM is aligned with the From: domain, so it would fail."))
        return out

    temporary = (spf and spf["result"] == "temperror") or any(s["result"] == "temperror" for s in dkim_sigs)
    if passed:
        how = " and ".join(n for n, ok in (("SPF", out["spf_aligned"]), ("DKIM", out["dkim_aligned"])) if ok)
        out["result"] = "pass"
        out["explanation"] = f"{how} passed for a domain aligned with the From: domain ({from_domain})."
    elif temporary:
        # RFC 7489 §6.6.2: a temporary SPF/DKIM error can't establish a DMARC failure
        out["result"] = "temperror"
        out["explanation"] = ("A temporary DNS error stopped SPF or DKIM, so DMARC couldn't be decided. "
                              "Send another test to try again.")
    else:
        out["result"] = "fail"
        out["explanation"] = ("Neither SPF nor DKIM passed for a domain aligned with the From: domain "
                              f"({from_domain}). " + POLICY_EFFECT[out["policy"]])
        if out["pct"] != "100" and out["policy"] != "none":
            out["explanation"] += f" (pct={out['pct']}: only that percentage of failures is affected.)"
    return out
