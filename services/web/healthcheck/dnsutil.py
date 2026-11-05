"""DNS lookups used by the checks, behind a small interface so tests can fake them.

SPF is the exception: pyspf does its own lookups through `spf.DNSLookup`, which spfcheck points at
`spf_lookup` here, so it gets fresh answers too.

Every lookup asks the domain's own (authoritative) nameservers directly (`resolve`), so a record changed a
minute ago is checked as it is now, not as a caching resolver last saw it. Only finding those nameservers
goes through the system resolver, since they rarely change. When the direct lookup can't get an answer
(the nameservers don't answer, or the host can only reach its own resolver), it falls back to the system
resolver, so a check is never worse off than before.
"""
import ipaddress
import logging
import random
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename

MAX_PTR_NAMES = 5  # PTR names checked forward; each one is another DNS lookup

SERVER_TIMEOUT = 1.5  # seconds per nameserver asked directly
MAX_SERVERS = 2  # nameservers tried per direct lookup before falling back
MAX_CNAMES = 8
DIRECT_SHARE = 0.6  # of a lookup's time, what the direct attempt may use: the rest is kept for the fallback
PAUSE_AFTER = 3  # direct lookups failing this many times in a row, while the root servers can't be reached
MIN_PROBE_SECONDS = 0.5  # less time than this to reach the root servers says nothing either way
PAUSE_SECONDS = 600  # either, use only the system resolver for this long (a host that can't reach port 53)

log = logging.getLogger("healthcheck.dns")
_failures = 0
_paused_until = 0.0


class Unavailable(Exception):
    """A direct lookup got no authoritative answer: use the system resolver instead."""


def resolve(name, rdtype, lifetime, recursive=None):
    """The records of type `rdtype` at `name`, fresh from its own nameservers when possible, within `lifetime`
    seconds. Raises what dns.resolver does: NXDOMAIN, NoAnswer, Timeout and the rest."""
    global _failures, _paused_until
    recursive = recursive or dns.resolver.get_default_resolver()
    start = time.monotonic()
    deadline = start + lifetime
    if start >= _paused_until:
        try:
            records = direct(name, rdtype, start + lifetime * DIRECT_SHARE, recursive)
        except Unavailable:
            _failures += 1
            if _failures >= PAUSE_AFTER:
                # one domain's broken nameservers mustn't switch fresh lookups off for everyone: pause only
                # when the root servers can't be reached either (half of what's left; the rest for the fallback)
                reachable = _roots_reachable(time.monotonic() + (deadline - time.monotonic()) / 2, recursive)
                if reachable:
                    _failures = 0
                elif reachable is False:
                    _failures, _paused_until = 0, time.monotonic() + PAUSE_SECONDS
                    log.warning("direct DNS lookups failed %d times in a row and the root servers can't be "
                                "reached: using the system resolver for %d minutes", PAUSE_AFTER, PAUSE_SECONDS // 60)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _failures = 0  # an authoritative "no such record" is an answer
            raise
        else:
            _failures = 0
            return records
    left = deadline - time.monotonic()
    if left <= 0:
        raise dns.exception.Timeout(timeout=lifetime)
    return list(recursive.resolve(name, rdtype, lifetime=left))


def direct(name, rdtype, deadline, recursive):
    """Ask the zone's own nameservers, following CNAMEs. Raises NXDOMAIN or NoAnswer when they say there's
    no such record, Unavailable when none of them gave an authoritative answer by `deadline`."""
    qname = name if isinstance(name, dns.name.Name) else dns.name.from_text(name)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    for _ in range(MAX_CNAMES + 1):
        response = _ask(qname, rdtype, _nameservers(qname, deadline, recursive), deadline)
        if response.rcode() == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response})
        answer = _rrset(response, qname, rdtype)
        if answer is not None:
            return list(answer)
        cname = _rrset(response, qname, dns.rdatatype.CNAME)
        if cname is None or rdtype == dns.rdatatype.CNAME:
            raise dns.resolver.NoAnswer(response=response)
        qname = cname[0].target  # asked afresh: the target may be in another zone
    raise Unavailable(f"more than {MAX_CNAMES} CNAMEs")


def _rrset(response, qname, rdtype):
    return next((r for r in response.answer
                 if r.name == qname and r.rdtype == rdtype and r.rdclass == dns.rdataclass.IN), None)


def _left(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise Unavailable("out of time")
    return left


def _roots_reachable(deadline, recursive):
    """Whether direct queries get out at all: True when a root server answers, False when none does, None
    when it can't be told (too little time, or their addresses couldn't be found)."""
    if deadline - time.monotonic() < MIN_PROBE_SECONDS:
        return None
    try:
        servers = _nameservers(dns.name.root, deadline, recursive)
    except Unavailable:
        return None
    if deadline - time.monotonic() < MIN_PROBE_SECONDS:  # finding them took the time
        return None
    try:
        _ask(dns.name.root, dns.rdatatype.NS, servers, deadline)
    except Unavailable:
        return False
    return True


def _public(address):
    """Only nameservers on the public internet are asked: a domain can't point its NS at a private, loopback,
    multicast or other special address and have the poller send DNS queries into the network it runs in.
    (is_global alone lets multicast through.)"""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def _nameservers(qname, deadline, recursive):
    """Public IPv4 addresses of the nameservers for the zone `qname` is in, in random order (to share the
    load), found through the system resolver."""
    try:
        zone = dns.resolver.zone_for_name(qname, resolver=recursive, lifetime=_left(deadline))
        hosts = [r.target for r in recursive.resolve(zone, "NS", lifetime=_left(deadline))]
        random.shuffle(hosts)
        addresses = []
        for host in hosts:
            if len(addresses) >= MAX_SERVERS:
                break
            try:
                found = [r.address for r in recursive.resolve(host, "A", lifetime=_left(deadline))
                         if _public(r.address)]
            except dns.exception.DNSException:
                continue  # this nameserver's address can't be found: the others may still do
            if found:
                addresses.append(random.choice(found))
    except dns.exception.DNSException as e:
        raise Unavailable(f"couldn't find the nameservers: {e}") from e
    if not addresses:
        raise Unavailable("no nameserver addresses")
    return addresses


def _ask(qname, rdtype, servers, deadline):
    """The first authoritative NOERROR or NXDOMAIN answer from `servers` (UDP, TCP when truncated)."""
    query = dns.message.make_query(qname, rdtype)
    query.flags &= ~dns.flags.RD  # an authoritative server answers from its own zone, never from a cache
    for server in servers:
        try:
            response = dns.query.udp(query, server, timeout=min(SERVER_TIMEOUT, _left(deadline)))
            if response.flags & dns.flags.TC:  # too big for UDP: again over TCP, in whatever time is left
                response = dns.query.tcp(query, server, timeout=min(SERVER_TIMEOUT, _left(deadline)))
        except Unavailable:
            raise
        except (dns.exception.DNSException, OSError, ValueError):
            continue
        if response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) and response.flags & dns.flags.AA:
            return response
    raise Unavailable("no authoritative answer")


def spf_lookup(name, qtype, strict=True, timeout=30):
    """pyspf's DNSLookup (same arguments and results as its dnspython one), through `resolve`."""
    import spf  # only here: dnsutil itself doesn't need pyspf
    try:
        records = resolve(name, qtype, timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise spf.TempError(f"DNS {e}") from e
    except dns.exception.DNSException:
        return []  # malformed name and the like, as Resolver does
    key = (name, qtype)
    if qtype in ("A", "AAAA"):
        return [(key, r.address) for r in records]
    if qtype == "MX":
        return [(key, (r.preference, r.exchange)) for r in records]
    if qtype == "PTR":
        return [(key, r.target.to_text(True)) for r in records]
    if qtype in ("TXT", "SPF"):
        return [(key, r.strings) for r in records]
    return []


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
        lifetime = min(self._timeout, left)
        self._resolver.lifetime = lifetime
        try:
            return resolve(name, rdtype, lifetime, self._resolver)
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
