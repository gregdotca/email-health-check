"""Find the Received: hop the receiving mail server (TRUSTED_MX_HOSTS) wrote when it accepted the message.

The receiving server's Exim prepends its headers, so reading from the top, the first hops are
internal (LMTP delivery, spam scanning, a relay from the backup MX) and the first
one after those is the trusted inbound hop. Everything below it was written by
the sender and can be forged, so we never look further down.
"""
import re
from dataclasses import asdict, dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime

from .settings import settings
import contextlib

MX_HOSTS = settings.trusted_mx_hosts  # TRUSTED_MX_HOSTS
INTERNAL_PROTOCOLS = {"lmtp", "spam-scanned", "local"}


@dataclass
class Hop:
    raw: str
    rdns: str = None
    helo: str = None
    ip: str = None
    by_host: str = None
    protocol: str = None
    envelope_from: str = None
    time: str = None  # ISO 8601, UTC

    @property
    def authenticated(self):
        # esmtpa / esmtpsa: a logged-in submission, not delivery from another server
        return bool(self.protocol) and self.protocol.endswith("a") and self.protocol.startswith("esmtp")

    def to_dict(self):
        return {**asdict(self), "authenticated": self.authenticated}


def unfold(value):
    return re.sub(r"\s+", " ", value).strip()


def parse_received(value):
    hop = Hop(raw=unfold(value))
    body, sep, date = hop.raw.rpartition(";")
    if sep:
        with contextlib.suppress(TypeError, ValueError):
            hop.time = parsedate_to_datetime(date.strip()).astimezone(UTC).isoformat()
    else:
        body = hop.raw

    m = re.match(r"from\s+(.*?)\s+by\s+(\S+)", body, re.I)
    if not m:
        m = re.match(r"()by\s+(\S+)", body, re.I)
    if m:
        hop.by_host = m.group(2).lower().rstrip(";")
        _parse_from_clause(hop, m.group(1))
        rest = body[m.end():]
        if pm := re.search(r"\bwith\s+(\S+)", rest, re.I):
            hop.protocol = pm.group(1).lower()
    if em := re.search(r"\(envelope-from <([^>]*)>\)", body, re.I):
        hop.envelope_from = em.group(1)
    return hop


def _parse_from_clause(hop, clause):
    """Exim writes `name ([ip])`, `name ([ip]) (helo=x)`, `name ([ip] helo=x)` or `[ip] (helo=x)`."""
    if not clause:
        return
    if im := re.search(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", clause):
        hop.ip = im.group(1)
    first = clause.split()[0]
    if first.startswith("("):
        hop.helo = first.strip("()")
    elif not first.startswith("["):
        hop.rdns = first.lower()
    if hm := re.search(r"helo=([^\s)\]]+)", clause, re.I):
        hop.helo = hm.group(1)
    elif hop.rdns and not hop.helo:
        hop.helo = hop.rdns  # Exim omits helo= when it matches the host name


def inbound_hop(received_values, mx_hosts=MX_HOSTS):
    """The hop where the receiving server accepted the message from the outside world, or None."""
    for value in received_values:
        hop = parse_received(value)
        if hop.by_host not in mx_hosts:
            return None  # not written by a trusted server: the format changed or something is off
        # A relay between trusted servers is identified by rDNS, never HELO: the sender
        # picks its HELO, but Exim only shows a host name it has verified in DNS.
        if hop.protocol in INTERNAL_PROTOCOLS or hop.rdns in mx_hosts:
            continue
        return hop
    return None
