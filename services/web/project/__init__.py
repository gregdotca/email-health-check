#!/usr/bin/env python3
import base64
import hashlib
import logging
import math
import os
import re
import sqlite3
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

from flask import Flask, abort, g, render_template, request
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix

from healthcheck import report
from healthcheck.mailer import reply_to
from healthcheck.settings import settings
from healthcheck.store import TOKEN, Store
from project.docs import docs as docs_blueprint

app = Flask(__name__, static_folder="assets")
app.config.update(DB_PATH=os.environ.get("DB_PATH", "health-check.sqlite3"), MAX_CONTENT_LENGTH=16 * 1024)
# TRUSTED_PROXY_HOPS (default 1: one reverse proxy in front); 0 when the page is reached directly
if settings.trusted_proxy_hops:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.trusted_proxy_hops)

APP_TITLE = settings.app_name
if not settings.public_url:
    # The poller keeps no reports without PUBLIC_URL (email-only), so this page would never find one
    logging.getLogger("project").warning("PUBLIC_URL isn't set: reports are only emailed, so this page won't find any")
ADDRESS = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")

CSP = {"default-src": ("'none'",), "style-src": ("'self'",), "img-src": ("'self'",), "form-action": ("'self'",),
       "frame-ancestors": ("'none'",), "base-uri": ("'none'",)}


class InlineCode(HTMLParser):
    """The CSP hashes of CUSTOM_HEADER_HTML's inline <script> and <style> blocks, so they run without allowing
    every inline script ('unsafe-inline'). Inline event handlers (onload=...) and style= attributes still
    don't run: CUSTOM_HEADER_CSP can't allow them."""

    def __init__(self, html):
        super().__init__(convert_charrefs=False)
        self.hashes, self.open, self.text = {"script-src": (), "style-src": ()}, None, []
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style") and not (tag == "script" and dict(attrs).get("src")):
            self.open, self.text = tag, []

    def handle_data(self, data):
        if self.open:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == self.open:
            digest = base64.b64encode(hashlib.sha256("".join(self.text).encode()).digest()).decode()
            self.hashes[tag + "-src"] += (f"'sha256-{digest}'",)
            self.open = None


def csp(*extras):
    """The Content-Security-Policy, with each {directive: sources} in extras added (replacing a 'none')."""
    policy = dict(CSP)
    for extra in extras:
        for directive, sources in extra.items():
            if sources:
                kept = tuple(s for s in policy.get(directive, ()) if s != "'none'")
                policy[directive] = tuple(dict.fromkeys(kept + tuple(sources)))
    return "; ".join(f"{d} {' '.join(sources)}" for d, sources in policy.items())


# CUSTOM_HEADER_HTML (the operator's own code: visitor statistics and the like) goes on every page but the report
# links, whose address (/<token>) opens a report: it mustn't reach someone else's statistics. Pages no
# route matched (404s) go without it too.
CUSTOM_HEADER_HTML = Markup(settings.custom_header_html)
NO_CUSTOM_HEADER_HTML = ("link_page", "link_results")
PLAIN_CSP = csp()
CUSTOM_CSP = csp(InlineCode(settings.custom_header_html).hashes, settings.custom_header_csp) if CUSTOM_HEADER_HTML else PLAIN_CSP

SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


def store():
    if "store" not in g:
        g.store = Store(app.config["DB_PATH"])
    return g.store


@app.after_request
def security_headers(response):
    response.headers.setdefault("Content-Security-Policy", CUSTOM_CSP if custom_header_here() else PLAIN_CSP)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def same_site(req):
    """False for a form posted from another website, so a third-party page can't start someone's
    5-minute clock. Sec-Fetch-Site decides when present (all current browsers send it). Origin is
    only a fallback for older browsers, and "null" proves nothing: our own pages send no-referrer,
    which makes browsers send "Origin: null" on their own form posts. Requests with neither header
    (curl, very old browsers) are allowed."""
    fetch_site = req.headers.get("Sec-Fetch-Site")
    if fetch_site is not None:
        return fetch_site in ("same-origin", "none")
    origin = req.headers.get("Origin")
    if not origin or origin == "null":
        return True
    try:
        return urlsplit(origin).netloc == req.host
    except ValueError:  # a malformed Origin (e.g. an unclosed "[") is no proof of anything: refuse
        return False


@app.errorhandler(sqlite3.OperationalError)
def database_busy(error):
    """The database stayed locked past its 10 s wait (or similar): a friendly retry, not a crash page."""
    return render_template("home.html", app_title=APP_TITLE,
                           error="The service is busy. Please try again in a moment."), 503


@app.context_processor
def docs_link():
    """The "Documentation" link in the page header, when the docs are on (DOCS_ENABLED)."""
    return {"docs_enabled": settings.docs_enabled}


def custom_header_here():
    """Not on the report links, nor on a page no route matched (/<token>/, /<token>/x... are 404s whose
    address still holds a token)."""
    return bool(CUSTOM_HEADER_HTML) and request.endpoint is not None and request.endpoint not in NO_CUSTOM_HEADER_HTML


@app.context_processor
def custom_header_html():
    """CUSTOM_HEADER_HTML for base.html's <head>, except on the report links."""
    return {"custom_header_html": CUSTOM_HEADER_HTML if custom_header_here() else ""}


@app.errorhandler(404)
def not_found(error):
    return render_template("home.html", app_title=APP_TITLE, missing_page=True), 404


@app.route("/", methods=["GET"])
def home():
    return render_template("home.html", app_title=APP_TITLE)


@app.route("/robots.txt")
def robots():
    """Keep every crawler off the whole site (the X-Robots-Tag header also says noindex)."""
    return "User-agent: *\nDisallow: /\n", {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/", methods=["POST"])
def lookup():
    """Look up by address (the homepage form and "Check again"). The address only travels in the
    POST body and the results show at "/", so it never lands in a URL, browser history or a log."""
    if not same_site(request):
        return render_template("home.html", app_title=APP_TITLE, error="Please use the form on this page."), 403
    address = request.form.get("address", "").strip()
    page = {"app_title": APP_TITLE, "address": address}
    if not ADDRESS.match(address):
        return render_template("home.html", error="Enter the email address you sent the test from.", **page), 400
    return show(page, lambda now: store().latest(address, now=now))


@app.route("/<token>", methods=["GET"])
def link_page(token):
    """The link in the results email: /<random token>. It only shows a "View Report" button, never the
    results, because mail systems' link scanners open every link in an email, and showing them here
    would start the 5-minute clock before the person clicked. It doesn't touch the database, so it
    looks the same for any well-formed token."""
    if not TOKEN.fullmatch(token):
        abort(404)
    return render_template("link.html", app_title=APP_TITLE)


@app.route("/<token>", methods=["POST"])
def link_results(token):
    """The results behind an email link (its "View Report" button posts here)."""
    if not same_site(request):
        return render_template("home.html", app_title=APP_TITLE, error="Please use the form on this page."), 403
    if not TOKEN.fullmatch(token):
        abort(404)
    return show({"app_title": APP_TITLE, "missing": "No report for that link"},
                lambda now: store().by_token(token, now=now))


def show(page, find):
    """Rate-limit, purge, find the result (which marks it viewed) and render the results page."""
    if not store().allow(request.remote_addr or ""):
        return render_template("home.html", error="Too many lookups from your network. Try again later.",
                               **page), 429
    store().purge()
    now = datetime.now(UTC).timestamp()
    r = find(now)
    if r:
        r["minutes_left"] = max(1, math.ceil((r["expires_at"] - now) / 60))
        page.setdefault("address", r.get("from") or "")
        # no results email went out for this test (a mailing list, Mailchimp and the like), so the page
        # mustn't send them to look for it. The poller decides it with its own addresses; results saved
        # before it did are judged here without them. (The sending caps aren't known either way.)
        expected = r["reply_expected"] if "reply_expected" in r else reply_to(r)[0]
        r["no_reply"] = not expected
    return render_template("results.html", r=r, **page)


app.register_blueprint(docs_blueprint)  # /docs/ (DOCS_ENABLED)
app.jinja_env.globals["app_title"] = APP_TITLE

for _name in ("verdict", "headers_filename", "ptr_status", "ptr_rows", "ptr_explanation", "spf_lookups", "dkim_summary",
              "received", "overview", "overview_status", "mark", "mark_verdict", "sender_domain"):
    app.add_template_filter(getattr(report, _name), _name)


if __name__ == "__main__":
    app.run()
