"""The documentation at /docs/ (DOCS_ENABLED, on by default): a few pages of plain HTML, with this
installation's own values (its test address, limits and retention times) filled in from the settings
and the code, so the docs always describe the instance they're on. Nothing here touches the database.

/docs and the old-style /help and /documentation addresses redirect (301) to /docs/; each page lives
at /docs/<slug>/ and its slash-less form redirects there. With DOCS_ENABLED=False they're all 404s.
"""
import os
from dataclasses import dataclass, field
from functools import cache

from flask import Blueprint, abort, redirect, render_template, url_for

from healthcheck import poller, report, store, summary_image
from healthcheck.analyze import MAX_HEADER_BYTES
from healthcheck.dkimcheck import EXPIRED, MAX_SIGNATURES, SHA1
from healthcheck.dkimcheck import EXPLANATIONS as DKIM_EXPLANATIONS
from healthcheck.dmarccheck import POLICY_EFFECT
from healthcheck.mailer import SKIP_LOCAL_PARTS
from healthcheck.settings import DEFAULTS, settings
from healthcheck.spfcheck import EXPLANATIONS as SPF_EXPLANATIONS
from healthcheck.spfcheck import MAX_LOOKUPS

docs = Blueprint("docs", __name__)

# The web service is given these two for the docs (never the mail passwords); either may be missing
TEST_ADDRESS = os.environ.get("RECEIVING_EMAIL_ADDRESS", "").strip()
_poll = os.environ.get("POLL_SECONDS", "").strip()
POLL_SECONDS = int(_poll) if _poll.isdigit() and int(_poll) >= poller.MIN_POLL_SECONDS else None


@dataclass(frozen=True)
class Page:
    slug: str  # "" for /docs/ itself
    title: str
    group: str
    lead: str  # one sentence under the title, also used on the index; {app} is APP_NAME
    toc: tuple = field(default=())  # (anchor, heading) for each h2 on the page, in order

    @property
    def url(self):
        return url_for("docs.page", slug=self.slug) if self.slug else url_for("docs.index")

    @property
    def template(self):
        return f"doc-pages/{self.slug or 'index'}.html"


# In reading order: the sidebar, the previous/next links and the index all follow this list
PAGES = (
    Page("", "Introduction", "Getting started",
         "What the {app} does, and how to receive your first report.",
         (("how-it-works", "How it works"), ("what-you-get", "What you get"), ("where-next", "Where to go next"))),
    Page("send-a-test", "Send a test", "Getting started",
         "Which address to send from, what to send, and where the report goes.",
         (("send", "Send the test"), ("who-gets-the-report", "Who gets the report"),
          ("not-answered", "Messages that aren't answered"), ("how-often", "How often you can test"))),
    Page("view-online", "View a report online", "Getting started",
         "Look up a report on this website, by the address you sent from or from the link in the email.",
         (("look-up", "Look up by address"), ("email-link", "The link in the email"),
          ("self-destruct", "Why reports self-destruct"), ("email-vs-web", "The website and the email"))),
    Page("the-report", "What's in the report", "Reading the report",
         "A walk through the report, from the summary at the top to the attachments.",
         (("email", "The email"), ("summary-box", "The summary"), ("message-box", "Message details"),
          ("check-boxes", "The four checks"), ("notes", "Notes and problems"), ("attachments", "Attachments"))),
    Page("summary", "The summary", "Reading the report",
         "The three answers at the top of every report, the marks next to them, and the rules behind each one.",
         (("at-a-glance", "At a glance"), ("marks", "Marks"), ("status", "Overall status"),
          ("send", "Can send email"), ("receive", "Can receive email"), ("authenticated", "Is authenticated"),
          ("examples", "Examples"))),
    Page("ptr", "PTR (reverse DNS)", "The checks",
         "Whether the sending server's IP address has a name that points back to it.",
         (("what-it-proves", "What it proves"), ("results", "Results"), ("rows", "What the box shows"),
          ("fixing", "Fixing it"))),
    Page("spf", "SPF", "The checks",
         "Whether the domain allows the server that sent the test to send its mail.",
         (("what-it-proves", "What it proves"), ("results", "Results"), ("rows", "What the box shows"),
          ("problems", "Problem notes"), ("fixing", "Fixing it"))),
    Page("dkim", "DKIM", "The checks",
         "Whether the message carries a valid signature, and whether it's for your own domain.",
         (("what-it-proves", "What it proves"), ("results", "Results"), ("rows", "What the box shows"),
          ("own-domain", "Your domain's signature"), ("fixing", "Fixing it"))),
    Page("dmarc", "DMARC", "The checks",
         "Whether the From: domain publishes a policy, and whether SPF or DKIM passed for that domain.",
         (("what-it-proves", "What it proves"), ("results", "Results"), ("alignment", "Alignment"),
          ("rows", "What the box shows"), ("problems", "Problem notes"), ("fixing", "Fixing it"))),
    Page("troubleshooting", "Troubleshooting", "Help",
         "What to do when no report arrives, or when it says something needs attention.",
         (("no-report", "No report arrived"), ("not-found", "No report on the website"),
          ("needs-attention", "The report says Needs Attention"), ("incomplete", "The report says Incomplete"),
          ("submitted", "Sent by logging in to the receiving server"))),
    Page("faq", "Common questions", "Help",
         "Answers for the situations people run into most: aliases, forwarding, subdomains, mail services and more.",
         (("sending", "Sending tests"), ("results", "Understanding the results"), ("online", "Reports online"),
          ("running", "Running your own"))),
    Page("privacy", "Privacy and limits", "Help",
         "What's kept, for how long, who can see it, and the limits that keep the service fair.",
         (("what-is-kept", "What's kept"), ("who-can-see", "Who can see a report"), ("limits", "Limits"),
          ("website", "The website"))),
    Page("glossary", "Glossary", "Help",
         "Short definitions of the email terms used in the reports and these pages.",
         (("terms", "Terms"),)),
    Page("how-it-works", "How it works", "Running your own",
         "The two services behind the health check, and what each check trusts.",
         (("services", "Two services"), ("one-test", "What happens to a test"), ("trust", "What's trusted"))),
    Page("setup", "Requirements and setup", "Running your own",
         "What you need to run your own health check, and how to set it up with Docker Compose.",
         (("requirements", "Requirements"), ("setup", "Setup"), ("web-or-email", "With or without the website"),
          ("docker", "Changing how Docker runs it"))),
    Page("settings", "Settings", "Running your own",
         "Every setting in the .env file, with its default.",
         (("mail", "Mail"), ("website", "Website and Compose"), ("app", "Reports and limits"),
          ("custom-header", "Your own code in the pages"), ("values", "Allowed values"))),
    Page("operations", "Running and updating", "Running your own",
         "Logs, updates, data and what the poller's log messages mean.",
         (("logs", "Logs"), ("updating", "Updating"), ("data", "Data"), ("log-messages", "Log messages"))),
)
BY_SLUG = {p.slug: p for p in PAGES}
GROUPS = tuple(dict.fromkeys(p.group for p in PAGES))

# The paths people guess: all permanent redirects to /docs/
ALIASES = ("/help", "/help/", "/documentation", "/documentation/")


def _minutes(seconds):
    return ", ".join(str(d // 60) for d in seconds[:-1]) + f" and {seconds[-1] // 60}"


def values():
    """This installation's numbers and names, as the pages show them."""
    return {
        "address": TEST_ADDRESS, "poll_seconds": POLL_SECONDS, "public_url": settings.public_url,
        "timezone": str(settings.display_timezone),
        "custom_header_html": bool(settings.custom_header_html),  # whether the pages carry the operator's own code
        "mail_hour": dict(store.MAIL_LIMITS)[3600], "mail_day": dict(store.MAIL_LIMITS)[86400],
        "mail_total": dict(store.MAIL_DAILY_LIMIT)[86400],
        "unviewed_hours": store.UNVIEWED_SECONDS // 3600, "viewed_minutes": store.VIEWED_SECONDS // 60,
        "lookups_minute": dict(store.RATE_LIMITS)[60], "lookups_hour": dict(store.RATE_LIMITS)[3600],
        "max_mb": poller.MAX_MESSAGE_BYTES // (1024 * 1024), "max_header_kb": MAX_HEADER_BYTES // 1024,
        "max_signatures": MAX_SIGNATURES, "max_lookups": MAX_LOOKUPS, "near_limit": MAX_LOOKUPS - 1,
        "retry_schedule": _minutes(poller.RETRY_DELAYS), "max_attempts": poller.MAX_SEND_ATTEMPTS,
        "retry_minutes": sum(poller.RETRY_DELAYS) // 60, "min_poll": poller.MIN_POLL_SECONDS,
        "skip_local_parts": sorted(SKIP_LOCAL_PARTS),
        "example_time": report.when(_EXAMPLE["arrived_at"]),
        "max_results": store.MAX_RESULTS, "max_per_poll": poller.MAX_PER_POLL,
    }


# Example results for the summary boxes on the pages: drawn by the same rules as real reports
_EXAMPLE = {"from": "you@example.com", "arrived_at": "2026-10-01T15:42:00+00:00", "mx": {"result": "pass"},
            "hop": {"ip": "192.0.2.25"}, "spf": {"result": "pass", "domain": "example.com", "lookups": 3},
            "dmarc": {"result": "pass", "record": "v=DMARC1; p=quarantine"}}
EXAMPLES = {
    "passed": {**_EXAMPLE, "dkim": [{"domain": "example.com", "result": "pass"}]},
    "esp-only": {**_EXAMPLE, "dkim": [{"domain": "mailservice.example.net", "result": "pass"}]},
    "no-spf": {**_EXAMPLE, "spf": {"result": "softfail", "domain": "example.com", "lookups": 3},
               "dkim": [{"domain": "example.com", "result": "pass"}]},
    "dns-error": {**_EXAMPLE, "mx": {"result": "temperror"}, "dkim": [{"domain": "example.com", "result": "pass"}]},
}


def explanations():
    """The wording each check's box uses, straight from the code."""
    return {"ptr": report.PTR_EXPLANATIONS, "spf": SPF_EXPLANATIONS,
            "dkim": {k: v.format(d="example.com") for k, v in DKIM_EXPLANATIONS.items()},
            "dkim_sha1": SHA1.format(d="example.com"), "dkim_expired": EXPIRED.format(d="example.com"),
            "dmarc_policy": POLICY_EFFECT}


@docs.before_request
def enabled():
    if not settings.docs_enabled:
        abort(404)


@docs.context_processor
def page_context():
    return {"pages": PAGES, "groups": GROUPS, "v": values(), "examples": EXAMPLES, "explain": explanations(),
            "defaults": DEFAULTS}


def render(page):
    i = PAGES.index(page)
    return render_template(page.template, page=page, prev=PAGES[i - 1] if i else None,
                           next=PAGES[i + 1] if i + 1 < len(PAGES) else None)


@docs.route("/docs/", merge_slashes=False)
def index():
    return render(BY_SLUG[""])


@docs.route("/docs", merge_slashes=False)
def no_slash():
    return redirect(url_for("docs.index"), 301)


@docs.route("/docs/<slug>/", merge_slashes=False)
def page(slug):
    if slug not in BY_SLUG or not slug:
        abort(404)
    return render(BY_SLUG[slug])


@docs.route("/docs/<slug>", merge_slashes=False)
def page_no_slash(slug):
    if slug not in BY_SLUG or not slug:
        abort(404)
    return redirect(url_for("docs.page", slug=slug), 301)


@docs.route("/docs/example-summary.png", merge_slashes=False)
def example_png():
    """The summary as it's attached to the report email, drawn from an example result."""
    return _example_png(), {"Content-Type": "image/png"}


@cache
def _example_png():
    return summary_image.render_png(EXAMPLES["esp-only"])


for _alias in ALIASES:
    docs.add_url_rule(_alias, f"alias{_alias.replace('/', '_')}", lambda: redirect(url_for("docs.index"), 301),
                      merge_slashes=False)
