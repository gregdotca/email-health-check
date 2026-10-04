"""Deployment settings, read once from the environment (the .env file). TRUSTED_MX_HOSTS is required;
the rest are optional, and an empty value means the default. Without PUBLIC_URL there's no web page:
the reports are only emailed, and nothing is kept for looking them up. A missing or bad value stops
the app at startup with the setting's name. `.env.example` lists them all.

The mail account settings (RECEIVING_EMAIL_*, SENDING_EMAIL_*, POLL_SECONDS) are read by poller.py.
docker-compose.yml passes these to the web service one by one (never the whole .env, which holds the
mail passwords), so a new setting here goes there too, and into .env.example.
"""
import os
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
}


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
    )


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
