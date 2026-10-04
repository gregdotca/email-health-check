"""Wording and summaries shared by the results email (text and HTML) and the web page."""
import re
from datetime import datetime

from .dmarccheck import aligned
from .settings import settings

TIMEZONE = settings.display_timezone  # DISPLAY_TIMEZONE (default UTC)


def ordinal(n):
    """1st, 2nd, 3rd, 4th, ... 11th, 12th, 13th, ... 21st, 22nd, 23rd, ..."""
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def when(iso):
    """An ISO time as e.g. "Thu, Oct 1st @ 4:49pm EDT"."""
    if not iso:
        return "unknown"
    t = datetime.fromisoformat(iso).astimezone(TIMEZONE)
    return (f"{t:%a, %b} {ordinal(t.day)} @ {t.hour % 12 or 12}:{t:%M}{'am' if t.hour < 12 else 'pm'}"
            f" {t:%Z}")


def received(r):
    """When the message arrived (the receiving server's Received time), else when it was analysed."""
    return when(r.get("arrived_at") or r.get("analyzed_at"))


def verdict(result):
    """good / bad / warn / neutral for a result word, used to colour its badge."""
    return {"pass": "good", "fail": "bad", "permerror": "bad", "softfail": "warn", "temperror": "warn",
            "quarantine": "warn", "reject": "bad", "mismatch": "bad",
            "All Tests Passed": "good", "Needs Attention": "bad", "Incomplete": "warn"}.get(result or "none", "neutral")


def ptr_status(r):
    """pass, mismatch (a PTR that doesn't point back), none, temperror or not checked."""
    iprev = r.get("iprev")
    if not iprev:
        return "not checked"
    if iprev["result"] == "fail":
        return "mismatch" if iprev["ptr"] else "none"
    return iprev["result"]


PTR_EXPLANATIONS = {
    "pass": "The sending IP's reverse DNS (PTR) name points back to the same IP. Many receivers expect this "
            "of a mail server.",
    "temperror": "A temporary DNS error stopped the lookup.",
    "mismatch": "The sending IP has a PTR record, but that name doesn't point back to the same IP, so receivers "
                "can't trust it.",
    "none": "The sending IP has no PTR record. Many receivers treat mail from an IP without reverse DNS as "
            "suspicious.",
    "not checked": "Not checked: the sending server couldn't be identified.",
}


DNS_FAILED = "DNS lookup failed"


def ptr_rows(r):
    """The PTR box's two rows: the PTR name resolved forward (domain -> IP), then the IP resolved
    back (IP -> domain). A DNS error shows in the row whose lookup failed."""
    ip, iprev = (r.get("hop") or {}).get("ip"), r.get("iprev") or {}
    if not ip or not iprev:
        return []
    names, failed = iprev.get("ptr") or [], iprev.get("failed")
    if failed == "ptr":
        return [("Domain -> IP", "(no PTR name to look up)"), ("IP -> Domain", f"{ip} -> {DNS_FAILED}")]
    name = failed or iprev.get("name") or (names[0] if names else None)
    if not name:
        domain_row = "(no PTR name to look up)"
    elif name == failed:
        domain_row = f"{name} -> {DNS_FAILED}"
    else:
        domain_row = f"{name} -> {', '.join((iprev.get('forward') or {}).get(name) or []) or '(no address)'}"
    return [("Domain -> IP", domain_row), ("IP -> Domain", f"{ip} -> {', '.join(names) or '(no PTR record)'}")]


def ptr_explanation(r):
    return PTR_EXPLANATIONS[ptr_status(r)]


def spf_lookups(spf):
    """The SPF box's "DNS lookups" row, e.g. "8 of 10" ("at least" when the count stopped short),
    or None when there's no record to count (and for results saved before lookups were counted)."""
    if not spf or spf.get("lookups") is None:
        return None
    return f"{'' if spf.get('lookups_exact', True) else 'at least '}{spf['lookups']} of 10"


def dkim_summary(sigs):
    results = [s["result"] for s in sigs or []]
    if "pass" in results:
        return "pass"
    return results[0] if results else "none"


MARKS = {True: "\u2713", False: "\u2717", None: "?", "warn": "!"}  # check mark, cross, not known, problem


DNS_ERROR = "couldn't be checked (DNS error)"
SUBMITTED = ("Can't tell from this test: it was sent by logging in to the same mail server, so it skipped "
             "the checks other receivers would make (see the note below)")


def authentication(r):
    """The "Is authenticated" row as (passed, detail). SPF alone decides yes or no. DKIM counts only when
    a signature for the From: domain passes; DMARC is named when it passes. Problems with something that
    is set up (a failing DKIM signature or DMARC check, DKIM only for another domain, DMARC without DKIM,
    a "Problem:" note on the SPF or DMARC record) make it "warn" (or keep it False), whatever SPF says;
    a check that couldn't finish (including the SPF record's lookup count) makes it None unless there's
    also a problem."""
    spf, sigs = r.get("spf"), r.get("dkim") or []
    dmarc_result = r.get("dmarc") or {}
    dmarc = dmarc_result.get("result")
    domain = sender_domain(r)
    own = [s for s in sigs if aligned(s["domain"], domain, "r")]  # signatures for the From: domain
    own_dkim = any(s["result"] == "pass" for s in own)
    # Submitted by logging in to the receiving server: no DKIM and SPF checked against the wrong server are the route's
    # doing, not the domain's, so only problems with the records themselves count
    submitted = bool((r.get("hop") or {}).get("authenticated"))

    # DMARC is set up if its record was found, even when its check couldn't finish (e.g. SPF timed out)
    dmarc_set_up = bool(dmarc_result.get("record")) or dmarc in ("pass", "fail", "permerror")

    problems = []
    # a permerror is the signature or its key being broken, whatever the route; on a submission a plain
    # "fail" isn't counted (the route explains enough already)
    problems += [f"DKIM: {result}" for result in dict.fromkeys(s["result"] for s in sigs)
                 if result == "permerror" or (result == "fail" and not submitted)]
    if dmarc == "permerror" or (dmarc == "fail" and not submitted):
        problems.append(f"DMARC: {dmarc}")
    elif dmarc_result.get("notes"):
        problems.append("a problem with the DMARC record (see below)")
    if spf and spf["result"] == "permerror" and submitted:
        problems.append("SPF: permerror")
    if spf and spf.get("notes"):
        problems.append("a problem with the SPF record (see below)")
    # (with signatures left unchecked, the domain's own may be among them: that's "unfinished" below)
    if not submitted and not r.get("dkim_unchecked"):
        if not own and any(s["result"] == "pass" for s in sigs):  # signed, but only by e.g. an ESP
            problems.append(f"no DKIM signature for {domain}")
        elif not sigs and dmarc_set_up:  # DMARC set up, DKIM not
            problems.append("no DKIM signature")

    unfinished = []
    errors = sum(s["result"] == "temperror" for s in sigs)
    if errors and not submitted:
        unfinished.append(f"{'a DKIM signature' if errors == 1 else f'{errors} DKIM signatures'} {DNS_ERROR}")
    if r.get("dkim_unchecked") and not submitted:
        n = r["dkim_unchecked"]
        unfinished.append(f"{n} DKIM signature{'s were' if n != 1 else ' was'}n't checked")
    if dmarc == "temperror" and not submitted:
        unfinished.append(f"DMARC {DNS_ERROR}")
    if spf and spf.get("lookups_exact") is False and not spf.get("notes"):
        # SPF's own verdict stands, but the walk through the record's includes stopped short
        unfinished.append("the SPF record's DNS lookups couldn't all be counted")

    if submitted:
        passed, text = None, SUBMITTED
    elif not spf or spf["result"] == "temperror":
        passed, text = None, f"SPF {DNS_ERROR}" if spf else "SPF: not checked"
    elif spf["result"] == "pass":
        passed, text = True, f"Yes ({', '.join(['SPF'] + ['DKIM'] * own_dkim + ['DMARC'] * (dmarc == 'pass'))})"
    else:
        passed, text = False, f"No (SPF: {spf['result']})"
    if problems and passed is not False:
        passed = "warn"  # a known problem outweighs an unfinished check
    elif unfinished and passed is True:
        passed = None
    extra = problems + unfinished
    if extra and submitted:
        text += ". Problems found anyway: " + ", ".join(extra)
    elif extra:
        text += (", but " if text.startswith("Yes") else ", and also ") + ", ".join(extra)
    return passed, text


WEB_UNKNOWN = "Unknown: this is only available in the emailed report"


def overview(r, web=False):
    """The at-a-glance box at the top: (passed, label, detail) rows, where passed is True, False, None
    (not known) or "warn" (works, but something set up is failing). The email can say the reply arrived,
    because the reader is holding it; the web page can't know, so it says so (a "?", which makes the web
    page's badge "Incomplete" at best)."""
    mail = r.get("mx")
    # never says which folder the test was found in (that's a detail of the receiving setup), so a "spam_folder" saved by
    # the previous version is ignored too
    send = (True, "The test message was sent successfully")
    if mail is None:
        receive = (None, "Not checked")
    elif mail["result"] == "pass":
        receive = (None, WEB_UNKNOWN) if web else (True, "The reply test message was received successfully")
    else:
        receive = {"none": (False, "No MX records"), "nullmx": (False, "Null MX: the domain accepts no mail"),
                   "temperror": (None, f"MX records {DNS_ERROR}")}[mail["result"]]
    authenticated = authentication(r)
    return [
        (send[0], "Can send email", send[1]),
        (receive[0], "Can receive email", receive[1]),
        (authenticated[0], "Is authenticated", authenticated[1]),
    ]


def overview_status(r, web=False):
    """The overview box's badge: "All Tests Passed", "Needs Attention" (a check failed) or "Incomplete".
    The web page can't know the reply arrived, so it never says "All Tests Passed": the full check is the
    email's."""
    passed = [row[0] for row in overview(r, web)]
    if False in passed or "warn" in passed:
        return "Needs Attention"
    return "All Tests Passed" if all(passed) else "Incomplete"


def mark(passed):
    return MARKS[passed]


def mark_verdict(passed):
    """good / bad / neutral / warn, to colour an overview row's mark."""
    return {True: "good", False: "bad", None: "neutral", "warn": "warn"}[passed]


def sender_domain(r):
    """The domain being tested: the From: address's domain."""
    return (r.get("from") or "").rpartition("@")[2] or "unknown"


def headers_filename(r):
    """`Email Headers (<sending domain>).txt`: the From: domain, else the envelope sender's."""
    address = r.get("from") or r.get("envelope_from") or ""
    domain = re.sub(r"[^a-z0-9.-]", "", address.rpartition("@")[2].lower()) or "unknown"
    return f"Email Headers ({domain}).txt"
