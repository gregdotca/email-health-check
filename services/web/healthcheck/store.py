"""SQLite store shared by the poller (writes results, counts emails) and the web app (reads, purges).

Results hold headers and computed checks only, never bodies: up to 24 hours unviewed, then 5 minutes
after the page first shows them (by default: see settings.py). Rate-limit hits are salted hashes of IPs or recipients, kept a day.
"""
import hashlib
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager

from .settings import settings

# Retention and limits come from settings.py
UNVIEWED_SECONDS = settings.results_kept_hours * 3600  # kept this long if nobody looks it up
VIEWED_SECONDS = settings.results_kept_after_view_minutes * 60  # then deleted this long after the first lookup that shows it
RATE_LIMITS = ((60, settings.lookups_per_minute), (3600, settings.lookups_per_hour))  # (window seconds, max lookups) per client IP
MAIL_LIMITS = ((3600, settings.mail_per_recipient_per_hour), (86400, settings.mail_per_recipient_per_day))  # results emails per recipient
MAIL_DAILY_LIMIT = ((86400, settings.mail_per_day),)  # results emails in total, from everyone: a hard daily ceiling
MAX_RESULTS = 500  # a ceiling on stored results; the oldest go first
HITS_KEPT_SECONDS = 86400  # longest window above

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY,
    stored_at REAL NOT NULL,
    viewed_at REAL,
    from_addr TEXT,
    envelope_from TEXT,
    data TEXT NOT NULL,
    token TEXT  -- the random code in the results email's link (/<token>); never derived from the address
);
CREATE INDEX IF NOT EXISTS results_from ON results (from_addr);
CREATE INDEX IF NOT EXISTS results_envelope ON results (envelope_from);
CREATE INDEX IF NOT EXISTS results_stored ON results (stored_at);
CREATE TABLE IF NOT EXISTS hits (
    client TEXT NOT NULL,  -- salted hash of the IP or recipient, never the value itself
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS hits_client ON hits (client, at);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# Not yet expired; parameters are (now - UNVIEWED_SECONDS, now - VIEWED_SECONDS)
# (written without bare NULL comparisons so that NOT _LIVE is never NULL)
_LIVE = "((viewed_at IS NULL AND stored_at >= ?) OR (viewed_at IS NOT NULL AND viewed_at >= ?))"


TOKEN = re.compile(r"[A-Za-z0-9_-]{22}")  # what new_token() makes; anything else isn't a results link


def new_token():
    """128 random bits, URL-safe: unguessable, and says nothing about who sent the message."""
    return secrets.token_urlsafe(16)


def _normalize(address):
    return (address or "").strip().lower() or None


class Store:
    def __init__(self, path):
        self.path = path
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
            if "token" not in [row[1] for row in db.execute("PRAGMA table_info(results)")]:
                db.execute("ALTER TABLE results ADD COLUMN token TEXT")  # databases from before 2026-10-01
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS results_token ON results (token)")
            db.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('salt', ?)", (secrets.token_hex(16),))
            self._salt = db.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()[0]

    @contextmanager
    def _connect(self, immediate=False):
        """A connection whose work commits (or rolls back) as one transaction. immediate=True takes
        the write lock before the first read, for read-then-write steps (rate limits, first view) that
        must not interleave with another web worker or the poller."""
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("PRAGMA secure_delete=ON")  # overwrite purged rows instead of leaving them in free pages
            with db:
                if immediate:
                    db.execute("BEGIN IMMEDIATE")
                yield db
        finally:
            db.close()

    def save(self, result, now=None):
        """Store a result; returns its random token (for the link in the results email)."""
        token = new_token()
        with self._connect() as db:
            db.execute(
                "INSERT INTO results (stored_at, from_addr, envelope_from, data, token) VALUES (?, ?, ?, ?, ?)",
                (now or time.time(), _normalize(result.get("from")), _normalize(result.get("envelope_from")),
                 json.dumps(result), token))
            # a hard ceiling, whatever arrives: keep the newest MAX_RESULTS
            db.execute("DELETE FROM results WHERE id NOT IN "
                       "(SELECT id FROM results ORDER BY stored_at DESC, id DESC LIMIT ?)", (MAX_RESULTS,))
        return token

    def update(self, token, **fields):
        """Change fields of a saved result (e.g. reply_expected once the email's fate is known)."""
        with self._connect(immediate=True) as db:
            row = db.execute("SELECT id, data FROM results WHERE token = ?", (token,)).fetchone()
            if row:
                db.execute("UPDATE results SET data = ? WHERE id = ?", (json.dumps({**json.loads(row[1]), **fields}),
                                                                        row[0]))

    def latest(self, address, now=None):
        """The newest result where the address is the From: or the envelope sender, or None.

        Showing it counts as viewing it: the first time starts its 5-minute clock (`expires_at`).
        Older results will never be shown, so they're deleted: those for the address looked up, and
        those for the shown result's From: address (else looking up the envelope address could leave
        an older From: result to resurface later). Not by envelope sender: services share those.
        """
        address = _normalize(address)
        if not address:
            return None
        now = now or time.time()
        with self._connect(immediate=True) as db:
            row = db.execute(
                "SELECT id, stored_at, viewed_at, data, from_addr FROM results "
                "WHERE (from_addr = ? OR envelope_from = ?) AND " + _LIVE + " ORDER BY stored_at DESC, id DESC",
                (address, address, now - UNVIEWED_SECONDS, now - VIEWED_SECONDS)).fetchone()
            return self._show(db, row, now, address)

    def by_token(self, token, now=None):
        """The result whose email link carries this token, or None; viewed the same way as latest()."""
        if not token:
            return None
        now = now or time.time()
        with self._connect(immediate=True) as db:
            row = db.execute(
                "SELECT id, stored_at, viewed_at, data, from_addr FROM results WHERE token = ? AND " + _LIVE,
                (token, now - UNVIEWED_SECONDS, now - VIEWED_SECONDS)).fetchone()
            return self._show(db, row, now)

    @staticmethod
    def _show(db, row, now, address=None):
        """Mark a result viewed (the first time starts its 5-minute clock) and delete the older results
        for its From: address and the address looked up; returns it with `expires_at`."""
        if not row:
            return None
        row_id, stored_at, viewed_at, data, from_addr = row
        if viewed_at is None:
            viewed_at = now
            db.execute("UPDATE results SET viewed_at = ? WHERE id = ?", (now, row_id))
        # Older results from the same sender only: the shown result's From:, or the address looked up as a
        # From:. Never other senders who share an envelope address (an ESP's bounce address), except
        # results with no From: at all, which only that envelope address can find.
        db.execute(
            "DELETE FROM results WHERE (stored_at < ? OR (stored_at = ? AND id < ?)) "
            "AND (from_addr = ? OR from_addr = ? OR (from_addr IS NULL AND envelope_from = ?))",
            (stored_at, stored_at, row_id, from_addr, address, address))
        return {**json.loads(data), "stored_at": stored_at, "expires_at": viewed_at + VIEWED_SECONDS}

    def allow(self, key, now=None, limits=RATE_LIMITS):
        """Record a hit for this key (a client IP, or a mail recipient); False if it's over any limit."""
        return self.allow_all([(key, limits)], now)

    def allow_all(self, checks, now=None):
        """[(key, limits), ...] as one transaction: True and a hit recorded for every key if none is over
        its limits, else False and nothing recorded (so an error or a refusal never counts one of them)."""
        now = now or time.time()
        clients = [(hashlib.sha256((self._salt + key).encode()).hexdigest(), limits) for key, limits in checks]
        with self._connect(immediate=True) as db:
            for client, limits in clients:
                for window, limit in limits:
                    count = db.execute("SELECT COUNT(*) FROM hits WHERE client = ? AND at > ?",
                                       (client, now - window)).fetchone()[0]
                    if count >= limit:
                        return False
            db.executemany("INSERT INTO hits (client, at) VALUES (?, ?)", [(client, now) for client, _ in clients])
        return True

    def purge(self, now=None):
        now = now or time.time()
        with self._connect() as db:
            db.execute("DELETE FROM hits WHERE at < ?", (now - HITS_KEPT_SECONDS,))
            return db.execute("DELETE FROM results WHERE NOT " + _LIVE,
                              (now - UNVIEWED_SECONDS, now - VIEWED_SECONDS)).rowcount
