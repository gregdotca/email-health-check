"""Deployment settings, read once from the environment (the .env file). TRUSTED_MX_HOSTS is required;
the rest are optional, and an empty value means the default. Without PUBLIC_URL there's no web page:
the reports are only emailed, and nothing is kept for looking them up. A missing or bad value stops
the app at startup with the setting's name. `.env.example` lists them all. CUSTOM_HEADER_HTML is the
operator's own HTML for the web pages (never in this repo), with CUSTOM_HEADER_CSP saying what it may load.

The mail account settings (RECEIVING_EMAIL_*, SENDING_EMAIL_*, POLL_SECONDS) are read by poller.py.
docker-compose.yml passes these to the web service one by one (never the whole .env, which holds the
mail passwords), so a new setting here goes there too, and into .env.example.
"""
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULTS = {
    "APP_NAME": "Email Health Check",  # page title, report heading, summary picture
    "PUBLIC_URL": "",  # the web page the results emails link to, e.g. https://check.example.com; empty: no web page
    # required: the receiving mail servers whose Received: headers are trusted (Exim's format), comma-separated
    "TRUSTED_MX_HOSTS": None,
    "DISPLAY_TIMEZONE": "UTC",  # times in the reports, e.g. America/New_York
    "TRUSTED_PROXY_HOPS": "1",  # reverse proxies in front of the web page (X-Forwarded-For hops trusted)
    "RESULTS_KEPT_HOURS": "24",  # a result is kept this long if nobody looks it up
    "RESULTS_KEPT_AFTER_VIEW_MINUTES": "5",  # then deleted this long after the page first shows it
    "LOOKUPS_PER_MINUTE": "10",  # web lookups per client IP
    "LOOKUPS_PER_HOUR": "60",
    "MAIL_PER_RECIPIENT_PER_HOUR": "5",  # results emails to one address
    "MAIL_PER_RECIPIENT_PER_DAY": "10",
    "MAIL_PER_DAY": "50",  # results emails in total, from everyone: a hard daily ceiling
    "DOCS_ENABLED": "True",  # the documentation at /docs/ on the web page (True or False)
    # True: a site for anyone, whose home page and docs say how to send a test (the test address, poll time);
    # False: a private site, just the form, and the web pages never name the test address or poll time
    "IS_PUBLIC_INSTANCE": "False",
    "CUSTOM_HEADER_HTML": "",  # HTML added to the <head> of the web pages (visitor statistics and the like)
    "CUSTOM_HEADER_CSP": "",  # what it may load, e.g. "script-src https://stats.example.com; connect-src ..."
}
# The Content-Security-Policy parts CUSTOM_HEADER_CSP may add sources to. The rest (default-src, form-action,
# frame-ancestors, base-uri...) stay as the app sets them.
CSP_DIRECTIVES = ("script-src", "style-src", "img-src", "connect-src", "font-src", "frame-src", "media-src",
                  "worker-src", "manifest-src")
# script-src sources that would run any inline script or onload= attribute, not just CUSTOM_HEADER_HTML's own blocks
UNSAFE_SCRIPT_SOURCES = ("'unsafe-inline'", "'unsafe-hashes'", "data:", "'unsafe-eval'")
# <script/> or <style/>: browsers ignore the slash and treat what follows as code, but the hashes would miss it
SELF_CLOSED_CODE = re.compile(r"<\s*(script|style)\b[^>]*/\s*>", re.I)


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    app_name: str
    public_url: str  # "": no web page
    trusted_mx_hosts: tuple
    display_timezone: ZoneInfo
    trusted_proxy_hops: int
    results_kept_hours: int
    results_kept_after_view_minutes: int
    lookups_per_minute: int
    lookups_per_hour: int
    mail_per_recipient_per_hour: int
    mail_per_recipient_per_day: int
    mail_per_day: int
    docs_enabled: bool
    is_public_instance: bool  # False (default): the web pages never show the test address or poll time
    custom_header_html: str  # "": none
    custom_header_csp: dict  # {directive: (source, ...)} added to the Content-Security-Policy


def load(env=os.environ):
    def get(name):
        value = (env.get(name) or "").strip() or DEFAULTS[name]  # "" stays "" for PUBLIC_URL (off)
        if value is None:
            raise SettingsError(f"{name} must be set (in .env): see .env.example")
        return value

    def whole(name, minimum=1):
        value = get(name)
        if not value.isdigit() or int(value) < minimum:
            raise SettingsError(f"{name} must be a whole number, at least {minimum} (got {value!r})")
        return int(value)

    def on_off(name):
        value = get(name)
        if value.lower() not in ("true", "false"):
            raise SettingsError(f"{name} must be True or False (got {value!r})")
        return value.lower() == "true"

    url = get("PUBLIC_URL").rstrip("/")
    if url and not _plain_site(url):
        raise SettingsError(f"PUBLIC_URL must be like https://example.com: no path, query, #fragment or "
                            f"user:password (got {url!r})")
    hosts = tuple(h.strip().lower().rstrip(".") for h in get("TRUSTED_MX_HOSTS").split(",") if h.strip())
    if not hosts:
        raise SettingsError("TRUSTED_MX_HOSTS must name at least one mail server")
    try:
        timezone = ZoneInfo(get("DISPLAY_TIMEZONE"))
    except (ZoneInfoNotFoundError, ValueError):
        raise SettingsError(f"DISPLAY_TIMEZONE must be a time zone like UTC or America/New_York "
                            f"(got {get('DISPLAY_TIMEZONE')!r})") from None
    return Settings(
        app_name=get("APP_NAME"), public_url=url, trusted_mx_hosts=hosts, display_timezone=timezone,
        trusted_proxy_hops=whole("TRUSTED_PROXY_HOPS", minimum=0),
        results_kept_hours=whole("RESULTS_KEPT_HOURS"),
        results_kept_after_view_minutes=whole("RESULTS_KEPT_AFTER_VIEW_MINUTES"),
        lookups_per_minute=whole("LOOKUPS_PER_MINUTE"), lookups_per_hour=whole("LOOKUPS_PER_HOUR"),
        mail_per_recipient_per_hour=whole("MAIL_PER_RECIPIENT_PER_HOUR"),
        mail_per_recipient_per_day=whole("MAIL_PER_RECIPIENT_PER_DAY"),
        mail_per_day=whole("MAIL_PER_DAY"),
        docs_enabled=on_off("DOCS_ENABLED"),
        is_public_instance=on_off("IS_PUBLIC_INSTANCE"),
        custom_header_html=_custom_header(get("CUSTOM_HEADER_HTML")),
        custom_header_csp=_csp_sources(get("CUSTOM_HEADER_CSP")),
    )


def _custom_header(value):
    """CUSTOM_HEADER_HTML as a browser reads it (a .env saved with Windows line endings), so the inline code's CSP
    hashes match. A self-closed <script/> or <style/> is refused: its code would never get a hash."""
    found = SELF_CLOSED_CODE.search(value)
    if found:
        raise SettingsError(f"CUSTOM_HEADER_HTML: write <{found[1].lower()}>...</{found[1].lower()}>, not "
                            f"{found[0]!r} (browsers don't treat it as closed)")
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _csp_sources(value):
    """CUSTOM_HEADER_CSP, "script-src https://a.example.com; connect-src https://a.example.com", as
    {"script-src": ("https://a.example.com",), ...}. Only the directives in CSP_DIRECTIVES, no 'none' or
    commas (a comma would start a second policy), and nothing in script-src that runs any inline script."""
    out = {}
    for part in value.split(";"):
        if not part.strip():
            continue
        directive, *sources = part.split()
        if directive.lower() not in CSP_DIRECTIVES:
            raise SettingsError(f"CUSTOM_HEADER_CSP can only add to {', '.join(CSP_DIRECTIVES)} (got {directive!r})")
        bad = [s for s in sources if "," in s or s.lower() == "'none'"]
        if not sources or bad:
            raise SettingsError(f"CUSTOM_HEADER_CSP: {directive} needs sources, like https://stats.example.com, "
                                f"without commas or 'none' (got {part.strip()!r})")
        unsafe = [s for s in sources if s.lower() in UNSAFE_SCRIPT_SOURCES]
        if directive.lower() == "script-src" and unsafe:
            raise SettingsError(f"CUSTOM_HEADER_CSP: script-src can't allow {' '.join(unsafe)}: it would let any "
                                f"inline script or code in a string run (put the code in a <script> block in "
                                f"CUSTOM_HEADER_HTML instead)")
        out[directive.lower()] = out.get(directive.lower(), ()) + tuple(sources)
    return out


def _plain_site(url):
    """http(s)://host[:port] and nothing else, since report links are this plus /<token>."""
    try:
        parts = urlsplit(url)
        port = parts.port  # raises on a bad port
    except ValueError:
        return False
    return (parts.scheme in ("https", "http") and bool(parts.hostname) and not parts.username
            and parts.password is None and not parts.path and not parts.query and not parts.fragment
            and "?" not in url and "#" not in url and (port is None or 0 < port < 65536))


settings = load()
