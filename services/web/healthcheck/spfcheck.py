"""SPF (RFC 7208) using the IP, HELO and envelope sender from the trusted inbound hop (received.py)."""
import contextlib
import re
import time

import spf

MAX_LOOKUPS = spf.MAX_LOOKUP  # 10 (RFC 7208 §4.6.4)
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}  # plus the redirect= modifier
MODIFIER = re.compile(r"([a-z][a-z0-9_.-]*)=(.*)", re.I)
PTR_MACRO = re.compile(r"%\{p", re.I)
# No real SPF term comes near this (a domain name is at most 253 characters), and pyspf's macro handling
# does quadratic work on long ones: a 60,000-character exists: took 26 s, past the 20 s budget
MAX_TERM = 512

EXPLANATIONS = {
    "pass": "The sending server's IP address is listed in the domain's SPF record.",
    "fail": "The domain's SPF record says this IP address may not send its mail (-all).",
    "softfail": "The domain's SPF record says this IP address probably shouldn't send its mail (~all). "
                "Most receivers accept it but treat it as suspicious.",
    "neutral": "The domain's SPF record makes no claim about this IP address (?all).",
    "none": "The domain has no SPF record.",
    "permerror": "The domain's SPF record is broken (a syntax error, more than one record, or more than "
                 "10 DNS lookups), so receivers treat it as an error.",
    "temperror": "A temporary DNS error stopped the check.",
}


class BoundedQuery(spf.query):
    """pyspf's query, refusing oversized input wherever evaluation fetches it (not just what the walk in
    count_lookups saw: an include named by a macro, records past the walk's cutoff, exp= text)."""

    def dns_spf(self, domain):
        record = super().dns_spf(domain)
        if record and any(len(t) > MAX_TERM for t in record.split(" ")):
            raise spf.PermError(f"a term in the SPF record is over {MAX_TERM} characters, too long to evaluate")
        return record

    def get_explanation(self, spec):
        """exp= text is expanded like a macro too: an oversized one is ignored, as pyspf ignores one with a
        syntax error. pyspf's own get_explanation, with the length check between fetching and expanding
        (fetched once: empty answers and failures aren't cached, so fetching twice could differ)."""
        if spec:
            try:
                texts = self.dns_txt(spec, ignore_void=True)
                if len(texts) == 1:
                    text = spf.to_ascii(texts[0])
                    if len(text) > MAX_TERM:
                        return None
                    return str(self.expand(text, stripdot=False))
            except spf.PermError:
                if self.strict > 1:  # as pyspf: only "harsh" mode reports it
                    raise
        elif self.strict > 1:
            raise spf.PermError("Empty domain-spec on exp=")
        return None


def check_spf(ip, helo, mail_from, timeout=10, budget=20):
    """Check the envelope sender, or postmaster@HELO for a null sender (bounces).

    timeout: seconds per DNS lookup; budget: seconds for the whole check (RFC 7208 suggests 20),
    after which it's a temperror. Without a budget, a record full of slow includes could run long.
    It also counts the DNS lookups the whole record needs (see count_lookups).
    """
    deadline = time.monotonic() + budget
    q = BoundedQuery(i=ip, s=mail_from or "", h=helo or "", timeout=timeout, querytime=budget)
    # The record and everything it includes are walked first (cheap, and the DNS answers are cached for
    # the check), so a record pyspf would choke on is never handed to it
    record = lookups = None
    exact, broken, oversized = True, [], False
    with contextlib.suppress(spf.PermError, spf.TempError):  # the check reports these itself
        record = q.dns_spf(q.o)
    if record:
        lookups, exact, broken, oversized = count_lookups(q, q.o.lower(), record, deadline)
    if oversized:
        result, detail = "permerror", (f"a term in the SPF record, or in a record it includes, is over {MAX_TERM} "
                                       "characters, too long to evaluate")
    else:
        try:
            result, _code, detail = q.check()
        except Exception as e:  # pyspf's own crash on a hostile record, e.g. a 4,400-digit macro (ValueError)
            result, detail = "permerror", f"the SPF record couldn't be evaluated ({type(e).__name__})"
    if result in ("none", "temperror"):
        record = None
    if not record:
        lookups, exact, broken = None, True, []
    return {
        "result": result,
        "domain": q.o.lower(),
        "record": record,
        "detail": detail,
        "explanation": EXPLANATIONS.get(result, ""),
        "lookups": lookups,
        "lookups_exact": exact,
        "notes": lookup_notes(lookups) + broken_notes(broken),
    }


def count_lookups(q, domain, record, deadline):
    """The DNS lookups evaluating this record can take: every include, a, mx, ptr and exists, and a
    redirect (ignored when there's an "all"), following includes and redirects (RFC 7208 §4.6.4).
    pyspf stops at the first match, so its own count is only what this message needed; a record
    over the limit can still pass for servers listed early in it.

    Returns (count, exact, broken, oversized). oversized: some record has a term over MAX_TERM. exact is False when the walk stopped short (a macro in an include,
    a DNS error, a loop, too deep, or out of time), so the count is a minimum. broken lists the
    (kind, domain, problem) of each include or redirect whose SPF record is missing, duplicated or invalid:
    this message may have passed before reaching it, but servers matched later get a permerror. Uses
    the query's DNS cache, so the records the check already fetched aren't looked up again.
    """
    total, exact, broken, oversized = 0, True, [], False

    def follow(target, chain, kind):
        nonlocal exact, oversized
        if not target:
            return  # a syntax error, which the check itself reports
        target = target.lower().rstrip(".")
        if "%" in target or target in chain or len(chain) > 10 or time.monotonic() > deadline:
            exact = False
            return
        try:
            q.void_lookups = 0  # pyspf counts empty answers across calls and gives up after 2
            found = q.dns_spf(target)
        except spf.TempError:
            exact = False
            return
        except spf.PermError as e:  # a permerror wherever evaluation reaches it
            problem = "has more than one SPF record" if "Two or more" in str(e) else "has an invalid SPF record"
            broken.append((kind, target, problem))
            return
        if not found:
            broken.append((kind, target, "has no SPF record"))
        elif any(len(t) > MAX_TERM for t in terms(found)):
            oversized = True  # never handed to pyspf: see MAX_TERM
            broken.append((kind, target, "has an SPF record with a syntax error"))
        elif not valid(found, target):
            broken.append((kind, target, "has an SPF record with a syntax error"))
        else:
            walk(found, chain + (target,))

    def valid(text, target):
        """False for a record with a permanent syntax error (e.g. ip4:198.51.100.999). The check only
        parses an included record when evaluation reaches it, so one after this message's match isn't
        caught there. Macros are checked too (an unknown one like %{z} is a permerror), except %{p}. Modifiers: like the
        check (strict, as pyspf runs by default), an empty redirect= or exp=, any modifier given twice or
        a modifier with a bad macro is a permerror (RFC 7208 §6)."""
        if any(len(t) > MAX_TERM for t in terms(text)):
            return False  # checked before any slow macro handling
        modifiers = [m for m in map(MODIFIER.fullmatch, terms(text)) if m]
        names = [m[1].lower() for m in modifiers]
        if len(names) != len(set(names)) or any(m[1].lower() in ("redirect", "exp") and not m[2] for m in modifiers):
            return False
        domain = q.d
        q.d = target  # what "a" and "mx" without a domain refer to
        try:
            for term in terms(text):
                if PTR_MACRO.search(term):  # skipped: expanding %{p} can mean a DNS lookup
                    continue
                modifier = MODIFIER.fullmatch(term)
                if not modifier:
                    q.validate_mechanism(term)
                elif modifier[1].lower() in ("redirect", "exp"):  # a domain: exp=localhost is a permerror
                    q.expand_domain(modifier[2])
                elif "%" in modifier[2]:  # e.g. x-note=%{z}
                    q.expand(modifier[2])
        except Exception:  # PermError, or pyspf's own crash on a hostile macro (ValueError)
            return False
        finally:
            q.d = domain
        return True

    def walk(text, chain):
        nonlocal total, exact, oversized
        found = terms(text)
        if any(len(t) > MAX_TERM for t in found):
            oversized = True
            return
        has_all = any(t.lstrip("+-~?").lower() == "all" for t in found)
        for term in found:
            if total > MAX_LOOKUPS * 4:
                exact = False
                return
            modifier = MODIFIER.fullmatch(term)
            if modifier:
                if modifier[1].lower() == "redirect" and not has_all:
                    total += 1
                    follow(modifier[2], chain, "redirect")
                continue
            mechanism = term.lstrip("+-~?")
            name = re.split(r"[:/]", mechanism, maxsplit=1)[0].lower()
            if name == "all":
                break  # evaluation never gets past "all": nothing after it costs a lookup or can break
            if name in LOOKUP_MECHANISMS:
                total += 1
                if name == "include":
                    follow(mechanism.partition(":")[2], chain, "include")

    walk(record, (domain,))
    return total, exact, list(dict.fromkeys(broken)), oversized


def terms(record):
    """A record's terms after "v=spf1", split on spaces only, as SPF does (RFC 7208 §4.6.1): a tab
    isn't a separator, so a term containing one is invalid, as pyspf finds when it reaches it."""
    return [t for t in record.split(" ") if t][1:]


def lookup_notes(lookups):
    """A "Problem:" note when the record is over the 10-lookup limit, or close to it."""
    if lookups is None or lookups < MAX_LOOKUPS - 1:
        return []
    if lookups > MAX_LOOKUPS:
        return [f"The SPF record needs {lookups} DNS lookups, but SPF allows {MAX_LOOKUPS}. Receivers "
                f"give permerror for any server not matched within the first {MAX_LOOKUPS}, so some of "
                "the domain's mail fails SPF."]
    return [f"The SPF record uses {lookups} of the {MAX_LOOKUPS} DNS lookups SPF allows. If it, or an "
            "include from a provider, ever needs more, mail from servers not matched within the first "
            f"{MAX_LOOKUPS} lookups fails SPF."]


def broken_notes(broken):
    """A "Problem:" note for each include or redirect whose SPF record is missing, duplicated or invalid."""
    return [f"{target} ({'an include' if kind == 'include' else 'the redirect'} in the SPF record) {problem}. "
            "Receivers give permerror for any server the record doesn't match before reaching it."
            for kind, target, problem in broken[:5]]
