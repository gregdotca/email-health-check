"""DNS lookups used by the checks, behind a small interface so tests can fake them.

SPF is the exception: pyspf does its own lookups through `spf.DNSLookup`.
"""
import ipaddress
import time

import dns.exception
import dns.resolver
import dns.reversename

MAX_PTR_NAMES = 5  # PTR names checked forward; each one is another DNS lookup


class DnsError(Exception):
    """A lookup failed for a temporary reason (timeout, SERVFAIL)."""


class Resolver:
    """One per message: each lookup gets `timeout` seconds, and all of them together `budget` seconds, so a
    domain whose DNS answers slowly can't hold the poller up for long (SPF has its own 20 s budget)."""

    def __init__(self, timeout=5.0, budget=30.0):
        self._resolver = dns.resolver.Resolver()
        self._timeout = timeout
        self._deadline = time.monotonic() + budget

    def _query(self, name, rdtype):
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise DnsError(f"{rdtype} lookup for {name} skipped: the time allowed for this message's DNS ran out")
        self._resolver.lifetime = min(self._timeout, left)
        try:
            return list(self._resolver.resolve(name, rdtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
            raise DnsError(f"{rdtype} lookup for {name} failed: {e}") from e
        except dns.exception.DNSException:
            return []  # malformed name and the like

    def txt(self, name):
        """Each TXT record as one string (multi-string records joined)."""
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def ptr(self, ip):
        name = dns.reversename.from_address(ip)
        return [r.target.to_text(omit_final_dot=True) for r in self._query(name, "PTR")]

    def addresses(self, name, rdtypes=("A", "AAAA")):
        return [r.address for rdtype in rdtypes for r in self._query(name, rdtype)]

    def mx(self, name):
        """(preference, host) pairs; a null MX ("0 .", RFC 7505) has host ""."""
        return [(r.preference, r.exchange.to_text(omit_final_dot=True).rstrip(".")) for r in self._query(name, "MX")]


def mx(resolver, domain):
    """Whether the domain can receive mail: "pass" (it has MX hosts), "none" (no MX records), "nullmx"
    (it says it accepts no mail) or "temperror"."""
    try:
        records = resolver.mx(domain)
    except DnsError:
        return {"result": "temperror"}
    hosts = [host for _, host in records if host]
    if records and not hosts:
        return {"result": "nullmx"}
    return {"result": "pass" if hosts else "none"}


def iprev(resolver, ip):
    """Forward-confirmed reverse DNS (RFC 8601 "iprev") for the connecting IP.

    `forward` maps each PTR name looked up to the addresses it resolves to. On a DNS error,
    `failed` says which lookup broke: "ptr" (IP -> name) or the PTR name whose A/AAAA lookup failed.
    """
    forward = {}
    try:
        names = resolver.ptr(ip)
    except DnsError as e:
        return {"result": "temperror", "ptr": [], "name": None, "forward": forward, "failed": "ptr", "error": str(e)}
    target = ipaddress.ip_address(ip)
    # only the sending IP's own family: a failing AAAA lookup can't hide an IPv4 match (or the reverse)
    rdtypes = ("A",) if target.version == 4 else ("AAAA",)
    failure = None  # the first PTR name whose lookup failed: a later name can still confirm the IP
    for name in names[:MAX_PTR_NAMES]:
        try:
            forward[name] = resolver.addresses(name, rdtypes)
        except DnsError as e:
            failure = failure or (name, str(e))
            continue
        if any(ipaddress.ip_address(a) == target for a in forward[name]):
            return {"result": "pass", "ptr": names, "name": name, "forward": forward}
    if failure:
        return {"result": "temperror", "ptr": names, "name": None, "forward": forward, "failed": failure[0],
                "error": failure[1]}
    return {"result": "fail", "ptr": names, "name": None, "forward": forward}
