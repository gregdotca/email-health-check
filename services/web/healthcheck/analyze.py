"""Turn one raw message into the results that get emailed back.

The result holds the header block and computed checks only; the body is used for
DKIM and then dropped with the raw bytes.
"""
import email
import email.policy
import re
from datetime import UTC, datetime
from email.header import decode_header, make_header
from email.utils import getaddresses

from . import dkimcheck, dmarccheck, received, spfcheck
from .dnsutil import Resolver, iprev, mx

# Every stored value except "headers" (capped by MAX_HEADER_BYTES) is cut to these, so a message
# with, say, a 300 KB Subject can't bloat the database
MAX_FIELD_CHARS = 2000
MAX_LIST_ITEMS = 50

WARN_AUTHENTICATED = (
    "This message was submitted by logging in to the same mail server that received it (with {protocol}), "
    "not delivered from another mail server. That happens when the sending domain is hosted on the same "
    "mail server as this check. That path isn't DKIM-signed, and SPF is checked against the server that "
    "logged in, so the results below don't show what other receivers would see."
)
WARN_NO_HOP = (
    "Couldn't find the receiving mail server's record of the server that delivered this message, so SPF "
    "and the connection details weren't checked."
)


# The same rules Python's email parser uses (email.feedparser): any of these line endings, and a line
# that doesn't look like a header ends the header block. Using its rules means the stored headers stop
# exactly where the parser's body begins, so no body text can end up in "headers".
LINE_END = re.compile(rb"\r\n|\r|\n")
HEADER_LINE = re.compile(rb"(From |[\041-\071\073-\176]*:|[\t ])")
MAX_HEADER_BYTES = 64 * 1024  # stored/attached headers are cut off here (real ones are a few KB)


SKIP_PRECEDENCE = {"bulk", "junk", "list", "auto_reply"}


COMMENT = re.compile(r"\([^()]*\)")  # an RFC 5322 comment (no nesting needed for a keyword)


def auto_submitted_keyword(value):
    """The keyword of an Auto-Submitted value (RFC 3834 §5.1): comments and ;parameters dropped,
    so "no; x-test=yes" and "no (not automatic)" both mean "no"."""
    value = str(value)[:MAX_FIELD_CHARS]
    for _ in range(5):  # peel a few levels of nested comments, then stop
        value = COMMENT.sub(" ", value)
    return value.split(";", 1)[0].strip().lower()


def automatic_reason(msg):
    """Why this message shouldn't get a results email, judged from its headers (all copies of
    each), or None. Run on the full headers: the stored copy may be cut off at MAX_HEADER_BYTES."""
    if any(auto_submitted_keyword(v) != "no" for v in msg.get_all("Auto-Submitted", [])):
        return "automatic message"
    if any(str(v).strip().lower() in SKIP_PRECEDENCE for v in msg.get_all("Precedence", [])):
        return "bulk or list message"
    if msg.get_all("List-Id") or msg.get_all("List-Unsubscribe"):
        return "mailing list message"
    return None


def header_block(raw):
    """The message's header block, without the blank line (or first non-header line) that ends it."""
    starts = []  # where each header line begins
    pos, end = 0, len(raw)
    for m in LINE_END.finditer(raw):
        line = raw[pos:m.start()]
        if not line or not HEADER_LINE.match(line):
            end = pos
            break
        starts.append(pos)
        pos = m.end()
    else:
        line = raw[pos:]
        if line and HEADER_LINE.match(line):
            starts.append(pos)
        elif line:
            end = pos
    # Like the parser: a last header line starting "From " (not the very first line) is really the
    # first line of the body
    if len(starts) > 1 and raw.startswith(b"From ", starts[-1]):
        end = starts[-1]
    return raw[:end].rstrip(b"\r\n")


def headers_text(raw):
    """The header block as text for storing, the web download and the email attachment: line
    endings made \\n, and cut off at MAX_HEADER_BYTES."""
    block = header_block(raw)
    text = LINE_END.sub(b"\n", block[:MAX_HEADER_BYTES]).decode("utf-8", "replace")
    if len(block) > MAX_HEADER_BYTES:
        text += f"\n[headers cut off at {MAX_HEADER_BYTES // 1024} KB]"
    return text


def _address(value):
    addrs = [a for _, a in getaddresses([value]) if a]
    return addrs[0].lower() if len(addrs) == 1 else None


def analyze(raw, resolver=None, now=None):
    resolver = resolver or Resolver()
    now = now or datetime.now(UTC)
    headers = header_block(raw)
    msg = email.message_from_bytes(headers + b"\r\n\r\n", policy=email.policy.compat32)
    warnings = []

    hop = received.inbound_hop(msg.get_all("Received", []))
    from_values = msg.get_all("From", [])
    from_addr = _address(from_values[0]) if len(from_values) == 1 else None
    from_domain = from_addr.rpartition("@")[2] if from_addr else None
    if len(from_values) != 1 or not from_addr:
        warnings.append("The message must have exactly one From: address for DMARC to apply.")

    if hop:
        envelope_from = (hop.envelope_from or "").lower()
    else:
        envelope_from = (_address(msg.get("Return-Path", "")) or "").lower()
        warnings.append(WARN_NO_HOP)
    if hop and hop.authenticated:
        warnings.append(WARN_AUTHENTICATED.format(protocol=hop.protocol))

    spf = ip_rev = None
    if hop and hop.ip:
        spf = spfcheck.check_spf(hop.ip, hop.helo, envelope_from)
        ip_rev = iprev(resolver, hop.ip)

    dkim = dkimcheck.verify_all(raw, resolver)
    if not dkim:
        warnings.append("The message has no DKIM signature.")
    signatures = len(msg.get_all("DKIM-Signature", []))
    if signatures > len(dkim):
        warnings.append(f"Only the first {len(dkim)} of {signatures} DKIM signatures were checked.")
    dmarc = dmarccheck.check_dmarc(resolver, from_domain, spf, dkim) if from_domain else None
    receiving = mx(resolver, from_domain) if from_domain else None

    def text(name):
        value = msg.get(name)
        return received.unfold(str(value)) if value is not None else None

    return bounded({
        "analyzed_at": now.isoformat(),
        "arrived_at": hop.time if hop else None,
        "from": from_addr,
        "envelope_from": envelope_from,
        "subject": decoded(text("Subject")),
        "date": text("Date"),
        "message_id": text("Message-ID"),
        "hop": hop.to_dict() if hop else None,
        "iprev": ip_rev,
        "spf": spf,
        "dkim": dkim,
        "dkim_unchecked": max(0, signatures - len(dkim)),  # past dkimcheck.MAX_SIGNATURES
        "dmarc": dmarc,
        "mx": receiving,
        "warnings": warnings,
        "automatic": automatic_reason(msg),  # decided here, on the full headers (see mailer.reply_to)
        "headers": headers_text(raw),
    })


def decoded(value):
    """A header's RFC 2047 encoded words decoded, e.g. Mailchimp's "=?utf-8?Q?=5BTest=5D=20Hello?=" as
    "[Test] Hello". The value is the sender's, so: it's cut to MAX_FIELD_CHARS first (Python's decoder
    does quadratic work on many encoded words), and a malformed encoding, an unknown charset or a result
    that isn't valid text (e.g. a lone surrogate from UTF-7) leaves the raw text."""
    if value is None or "=?" not in value:
        return value
    cut = len(value) > MAX_FIELD_CHARS
    value = value[:MAX_FIELD_CHARS]
    try:
        text = received.unfold(str(make_header(decode_header(value))))
        text.encode("utf-8")  # raises on surrogates, which would crash the email and the web page
    except Exception:  # HeaderParseError, LookupError (charset), UnicodeError, and the like
        text = value
    return text + "\u2026" if cut else text


def bounded(value, key=None):
    """The result with every string cut to MAX_FIELD_CHARS and every list to MAX_LIST_ITEMS
    ("…" marks a cut); "headers" has its own, larger cap."""
    if key == "headers":
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + "…"
    if isinstance(value, dict):
        return {k: bounded(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [bounded(v) for v in value[:MAX_LIST_ITEMS]]
    return value
