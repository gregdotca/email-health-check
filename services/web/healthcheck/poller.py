"""Poll the test mailbox: analyze each message, save the result for the web page (store.py
retention; only when PUBLIC_URL is set), email the results back to the sender, delete the original.
Bodies are never kept.

Settings come from the environment:
  RECEIVING_EMAIL_HOST, RECEIVING_EMAIL_USER, RECEIVING_EMAIL_PASSWORD  IMAP login
  RECEIVING_EMAIL_ADDRESS  the address people send tests to (never answered, nor is its domain);
    often the same as RECEIVING_EMAIL_USER, but not when the test address is an alias
  SENDING_EMAIL_HOST, SENDING_EMAIL_PORT (587), SENDING_EMAIL_USE_TLS (True),
  SENDING_EMAIL_HOST_USER, SENDING_EMAIL_HOST_PASSWORD,
  SENDING_EMAIL_FROM (default: RECEIVING_EMAIL_ADDRESS),
  SENDING_EMAIL_FROM_NAME (default: APP_NAME)  report emails
  (subject: "Report for <sender's domain>")
  POLL_SECONDS (required: seconds between mailbox checks, at least 10; e.g. 30)
  DB_PATH (rate-limit counters only),
  DRY_RUN=True (read-only: nothing is flagged, deleted or sent)
True/False settings take True or False (any capitalization); anything else stops the poller.
Everything else (public URL, trusted MX hosts, time zone, limits) is in settings.py.

`python -m healthcheck.poller --check-smtp` tests the sending settings without sending anything.

Logs say how many messages were handled, never who sent them.
"""
import email
import email.policy
import imaplib
import logging
import os
import re
import signal
import sqlite3
import ssl
import sys
import threading
import time
from datetime import UTC, datetime

from .analyze import _address, analyze, bounded, header_block, headers_text
from .mailer import Mailer, SendError, describe, reply_to, report_sender
from .settings import settings
from .store import MAIL_DAILY_LIMIT, MAIL_LIMITS, Store
import contextlib

log = logging.getLogger("healthcheck.poller")

JUNK_NAMES = {"junk", "spam", "inbox.junk", "inbox.spam", "junk e-mail", "junk email", "bulk mail"}
LIST_LINE = re.compile(r'\((?P<flags>[^)]*)\) (?:"[^"]*"|NIL) (?P<name>.+)')
# After a temporary send failure, wait this long before each retry (1, 2, 5, 10, 20 minutes:
# ~38 minutes in all, gentle on the SMTP service), then give up. The message stays in the mailbox meanwhile.
RETRY_DELAYS = (60, 120, 300, 600, 1200)
MAX_SEND_ATTEMPTS = len(RETRY_DELAYS) + 1
MAX_MESSAGE_BYTES = 1024 * 1024  # bigger messages are deleted without being downloaded (tests are tiny)
SIZE = re.compile(rb"RFC822\.SIZE (\d+)")
AUTH_FAILED_WAIT = 300  # repeated bad logins get the IP blocked, so back off hard
ERROR_WAIT = 30
MIN_POLL_SECONDS = 10  # anything shorter would hammer the mailbox
MAX_PER_POLL = 20  # messages handled per check; the rest wait for the next one (cleanup runs between)
PURGE_EVERY = 60  # expired results are cleared at least this often, even mid-batch
FOLDERS_REFRESH = 3600  # the folder list is fetched once, then again hourly (or if a folder won't open)


def quote(name):
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def find_folders(conn):
    """INBOX plus any folder flagged \\Junk or named like a spam folder; None if LIST failed (so a
    one-off failure isn't mistaken for "there's only INBOX")."""
    typ, data = conn.list()
    if typ != "OK":
        return None
    folders = ["INBOX"]
    for line in data:
        m = LIST_LINE.match(line.decode("utf-8", "replace") if isinstance(line, bytes) else line)
        if not m:
            continue
        name = m.group("name").strip()
        if name.startswith('"'):
            name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        if ("\\junk" in m.group("flags").lower() or name.lower() in JUNK_NAMES) and name not in folders:
            folders.append(name)
    return folders


def fallback_result(raw, error):
    """Enough for the web page to show that the message arrived but couldn't be checked."""
    msg = email.message_from_bytes(header_block(raw) + b"\r\n\r\n", policy=email.policy.compat32)
    return bounded({
        "error": f"The message arrived but couldn't be analysed ({type(error).__name__}).",
        "analyzed_at": datetime.now(UTC).isoformat(),
        "from": _address(str(msg.get("From", ""))),
        "envelope_from": _address(str(msg.get("Return-Path", ""))),
        "subject": str(msg.get("Subject", "")),
        "headers": headers_text(raw),
        "warnings": [],
    })


class Poller:
    def __init__(self, store, mailer, dry_run=False, analyze=analyze, own_addresses=(), own_domain=None,
                 clock=time.time, keep_results=True):
        self.store = store
        self.keep_results = keep_results  # False without a web page (no PUBLIC_URL): nothing to look up
        self.dry_run = dry_run
        self.analyze = analyze
        self.mailer = mailer
        self.own_addresses = own_addresses
        self.own_domain = own_domain
        self.seen = set()  # dry run only: (folder, uidvalidity, uid) already handled
        self.clock = clock
        self.pending = {}  # message key -> (result, attempts so far, time of next try) for sends to retry
        self.undeleted = set()  # handled messages whose \Deleted flag couldn't be set yet
        self.folders, self.folders_at = None, None  # last good folder list, and when it was fetched
        self.turn = 0  # which folder goes first this check, so a busy INBOX can't starve Junk
        self.size_unknown = set()  # messages whose size the IMAP server didn't report (already logged)
        self.purged_at = clock()  # expired results are also cleared between messages in a long batch

    def process(self, raw, key=None):
        """Analyse and answer one message. False means keep it in the mailbox: the send failed
        temporarily and will be retried after a delay (RETRY_DELAYS)."""
        retry = key is not None and key in self.pending
        counted = False  # whether this email has been counted against the sending limits yet
        if retry:
            result, attempts, _, counted = self.pending.pop(key)
        else:
            try:
                result = self.analyze(raw)
            except Exception as e:
                # the type only: exception text can quote the message's headers and addresses
                log.error("analysis failed (%s); no results email", type(e).__name__)
                self.save(fallback_result(raw, e))
                return True
            # for the web page, which doesn't have this tool's own addresses to judge it (not the caps:
            # those are only known when sending)
            result["reply_expected"] = bool(reply_to(result, self.own_addresses, self.own_domain)[0])
            self.save(result)
            attempts = 0
        status, counted = self.send_results(result, retry=retry, counted=counted)
        if status != "retry":
            if status != "sent" and result.get("reply_expected"):
                self.no_reply(result)
            return True
        attempts += 1
        if key is None or attempts >= MAX_SEND_ATTEMPTS:
            log.error("giving up on a results email after %d attempt(s)", attempts)
            self.no_reply(result)
            return True
        delay = RETRY_DELAYS[attempts - 1]
        self.pending[key] = (result, attempts, self.clock() + delay, counted)
        log.warning("will retry the results email in %d min (attempt %d of %d failed)",
                    delay // 60, attempts, MAX_SEND_ATTEMPTS)
        return False

    def save(self, result):
        """Keep the result for the web page (dry runs too, so the dev page has something to show), if
        there is one. A failure is logged; the email still goes out."""
        if not self.keep_results:
            return
        try:
            result["token"] = self.store.save(result)  # the results email links to /<token>
        except Exception as e:
            log.error("saving the result for the web page failed (%s)", type(e).__name__)

    def no_reply(self, result):
        """The results email didn't go out after all (a limit, a failure): tell the web page, so it
        doesn't send the person looking for it. A failure here is logged, never fatal."""
        result["reply_expected"] = False
        if result.get("token") and self.keep_results:
            try:
                self.store.update(result["token"], reply_expected=False)
            except Exception as e:
                log.error("updating the saved result failed (%s)", type(e).__name__)

    def send_results(self, result, retry=False, counted=False):
        """Email the result to the sender. Returns (status, counted): status is "sent", "skipped",
        "retry" (temporary failure: keep the message) or "failed"; counted says whether it has been
        counted against the sending limits (each email is counted once, even over retries). A failure
        is logged and never stops the poller."""
        to, reason = reply_to(result, self.own_addresses, self.own_domain)
        if not to:
            log.info("no results email: %s", reason)
            return "skipped", counted
        if self.dry_run:
            log.info("dry run: would have sent a results email")
            return "skipped", counted
        if not counted:
            try:
                # the recipient's limits and the daily total together: both counted, or neither
                allowed = self.store.allow_all([("mail:" + to, MAIL_LIMITS), ("mail:*", MAIL_DAILY_LIMIT)])
            except sqlite3.Error as e:  # e.g. the database stayed locked: try again later, keep the message
                log.error("checking the sending limits failed (%s); will retry", type(e).__name__)
                return "retry", False
            if not allowed:
                log.warning("no results email: rate limit reached")
                return "skipped", True
            counted = True
        try:
            self.mailer.send(result, to)
        except SendError as e:
            log.error("sending the results email failed while %s", e)
            return ("retry" if e.temporary else "failed"), counted
        except Exception as e:
            # building the email broke on something unexpected in the message: give up on this one
            # email, never the poller (the type only: the text could quote the message)
            log.error("building the results email failed (%s)", type(e).__name__)
            return "failed", counted
        log.info("sent a results email%s", " (retry)" if retry else "")
        return "sent", counted

    def poll_once(self, conn):
        handled = 0
        if self.folders_at is None or self.clock() - self.folders_at >= FOLDERS_REFRESH:
            listed = find_folders(conn)
            if listed is None:  # keep what we had (or just INBOX) and try listing again next poll
                log.warning("couldn't list the mail folders; will try again next poll")
                self.folders, self.folders_at = self.folders or ["INBOX"], None
            else:
                self.folders, self.folders_at = listed, self.clock()
        start = self.turn % len(self.folders)
        self.turn += 1
        for folder in self.folders[start:] + self.folders[:start]:
            if handled >= MAX_PER_POLL:
                break
            typ, _ = conn.select(quote(folder), readonly=self.dry_run)
            if typ != "OK":
                self.folders_at = None  # renamed or gone: list the folders again next poll
                continue
            uidvalidity = (conn.response("UIDVALIDITY")[1] or [None])[0]
            # UNDELETED: a message already flagged but not yet expunged is never handled twice
            typ, data = conn.uid("SEARCH", None, "UNDELETED")
            deleted = 0
            for uid in (data[0] or b"").split() if typ == "OK" else []:
                if handled >= MAX_PER_POLL:
                    break
                if self.clock() - self.purged_at >= PURGE_EVERY:  # a slow batch mustn't delay the clean-up
                    purge(self.store)
                    self.purged_at = self.clock()
                key = (folder, uidvalidity, uid)
                if key in self.seen:
                    continue
                if key in self.undeleted:  # already answered; only the delete is left to do
                    deleted += self.delete(conn, key)
                    continue
                if key in self.pending and self.clock() < self.pending[key][2]:
                    continue  # waiting for its next retry: not downloaded, not counted
                size = self.size(conn, uid)
                if size is None:  # never download a message of unknown size: try again next check
                    if key not in self.size_unknown:
                        log.warning("couldn't get a message's size; will try again next poll")
                        self.size_unknown.add(key)
                    continue
                self.size_unknown.discard(key)
                raw = None
                if size <= MAX_MESSAGE_BYTES:
                    typ, parts = conn.uid("FETCH", uid, "(BODY.PEEK[])")
                    raw = next((p[1] for p in parts or [] if isinstance(p, tuple)), None)
                    if typ != "OK" or raw is None:
                        continue
                if size > MAX_MESSAGE_BYTES or len(raw) > MAX_MESSAGE_BYTES:  # second check: what arrived
                    log.warning("message too large (%d bytes), deleted without being checked",
                                max(size, len(raw or b"")))
                    done = True
                else:
                    try:
                        done = self.process(raw, key)
                    except Exception as e:  # never let one message stop the poller
                        log.error("handling a message failed (%s); deleting it", type(e).__name__)
                        done = True
                handled += 1
                if self.dry_run:
                    self.seen.add(key)
                elif done:
                    deleted += self.delete(conn, key)
            if deleted:
                typ, _ = conn.expunge()
                if typ != "OK":
                    # the messages stay flagged \Deleted, so UNDELETED skips them; CLOSE removes them too
                    log.error("expunge failed in a mail folder; flagged messages will be removed later")
            conn.close()
        return handled

    def size(self, conn, uid):
        typ, parts = conn.uid("FETCH", uid, "(RFC822.SIZE)")
        for part in parts or [] if typ == "OK" else []:
            m = SIZE.search(part[0] if isinstance(part, tuple) else part or b"")
            if m:
                return int(m.group(1))
        return None

    def delete(self, conn, key):
        """Flag a handled message \\Deleted. 1 if flagged; on failure it's remembered and retried on
        the next poll, without being answered again."""
        first_try = key not in self.undeleted
        # remembered before trying, so even a connection that drops mid-STORE can't lead to a second
        # reply: on the next connection the message is only deleted
        self.undeleted.add(key)
        typ, _ = conn.uid("STORE", key[2], "+FLAGS.SILENT", "(\\Deleted)")
        if typ == "OK":
            self.undeleted.discard(key)
            return 1
        if first_try:
            log.error("couldn't flag a handled message for deletion; will try again next poll")
        return 0


def connect(server, user, password):
    # an explicit context: imaplib's default doesn't check the server's certificate
    conn = imaplib.IMAP4_SSL(server, 993, ssl_context=ssl.create_default_context(), timeout=60)
    conn.login(user, password)
    return conn


def purge(store):
    """Delete expired results and old rate-limit hits; a failure is logged, never fatal."""
    try:
        store.purge()
    except Exception as e:
        log.error("cleaning up expired results failed (%s)", type(e).__name__)


def wait_purging(stop, store, seconds, every=60):
    """Wait (until stopped), cleaning up at least once a minute, so expired results are deleted on
    time even while the mail server is unreachable or a login keeps failing."""
    end = time.time() + seconds
    while not stop.is_set():
        purge(store)
        left = end - time.time()
        if left <= 0:
            return
        stop.wait(min(every, left))


def poll_seconds(value):
    """POLL_SECONDS as an int, or None if it isn't a whole number >= MIN_POLL_SECONDS."""
    value = value.strip()
    return int(value) if value.isdigit() and int(value) >= MIN_POLL_SECONDS else None


def true_false(value, default):
    """A True/False setting (any capitalization): True, False, the default when empty, or None for anything
    else, so a typo (or a yes/no, 1/0) can't flip it."""
    value = value.strip().lower()
    if not value:
        return default
    return {"true": True, "false": False}.get(value)


def smtp_port(value):
    """SENDING_EMAIL_PORT as an int (587 when empty), or None if it isn't a port number."""
    value = value.strip() or "587"
    return int(value) if value.isdigit() and 1 <= int(value) <= 65535 else None


def check_smtp(mailer):
    """`python -m healthcheck.poller --check-smtp`: show the sending settings (no secrets) and try to
    connect, start TLS and log in, without sending anything."""
    print(f"host={mailer.host!r} port={mailer.port} use_tls={mailer.use_tls} "
          f"user={'set' if mailer.user else 'NOT SET'} password={'set' if mailer.password else 'NOT SET'} "
          f"from={mailer.from_addr!r} from_name={mailer.from_name!r}")
    try:
        mailer.check()
    except SendError as e:
        print(f"FAILED while {e}")
        return 1
    steps = ["connected"] + ["started TLS"] * bool(mailer.use_tls) + ["logged in"] * bool(mailer.user)
    print(f"OK: {', '.join(steps[:-1]) + ' and ' if len(steps) > 1 else ''}{steps[-1]} (nothing was sent)")
    return 0


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    env = os.environ
    missing = [k for k in ("RECEIVING_EMAIL_HOST", "RECEIVING_EMAIL_ADDRESS", "RECEIVING_EMAIL_USER", "RECEIVING_EMAIL_PASSWORD",
                           "SENDING_EMAIL_HOST", "POLL_SECONDS") if not env.get(k)]
    if missing:
        log.error("missing settings: %s%s", ", ".join(missing),
                  " (RECEIVINT_EMAIL_PASSWORD is set: fix the spelling)" if env.get("RECEIVINT_EMAIL_PASSWORD") else "")
        sys.exit(2)
    interval = poll_seconds(env["POLL_SECONDS"])
    if interval is None:
        log.error("POLL_SECONDS must be a whole number of seconds, at least %d", MIN_POLL_SECONDS)
        sys.exit(2)
    dry_run = true_false(env.get("DRY_RUN", ""), False)
    if dry_run is None:
        log.error("DRY_RUN must be True or False")
        sys.exit(2)
    store = Store(env.get("DB_PATH", "health-check.sqlite3"))
    mailbox = env["RECEIVING_EMAIL_ADDRESS"]  # the test address
    login = env["RECEIVING_EMAIL_USER"]  # the IMAP login: often the same, but not for an alias
    from_addr, from_name = report_sender(env, mailbox)
    port, use_tls = smtp_port(env.get("SENDING_EMAIL_PORT", "")), true_false(env.get("SENDING_EMAIL_USE_TLS", ""), True)
    if port is None or use_tls is None:
        log.error("%s", "SENDING_EMAIL_PORT must be a port number (e.g. 587)" if port is None else
                  "SENDING_EMAIL_USE_TLS must be True or False")  # never guess: a typo mustn't turn TLS off
        sys.exit(2)
    mailer = Mailer(env["SENDING_EMAIL_HOST"], port, use_tls,
                    env.get("SENDING_EMAIL_HOST_USER"), env.get("SENDING_EMAIL_HOST_PASSWORD"),
                    from_addr, from_name)
    if "--check-smtp" in sys.argv:
        sys.exit(check_smtp(mailer))
    poller = Poller(store, mailer, dry_run=dry_run, own_addresses=(mailbox, from_addr),
                    own_domain=mailbox.rpartition("@")[2], keep_results=bool(settings.public_url))

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    log.info("poller started%s, every %ds%s", " (DRY RUN: nothing is deleted or sent)" if dry_run else "",
             interval, "" if settings.public_url else "; no PUBLIC_URL, so reports are only emailed")

    while not stop.is_set():
        conn = None
        try:
            conn = connect(env["RECEIVING_EMAIL_HOST"], login, env["RECEIVING_EMAIL_PASSWORD"])
            while not stop.is_set():
                handled = poller.poll_once(conn)
                if handled:
                    log.info("handled %d message(s)", handled)
                wait_purging(stop, store, interval)  # expired results go even between polls (web purges too)
        except imaplib.IMAP4.error as e:
            wait = AUTH_FAILED_WAIT if "AUTHENTICATIONFAILED" in str(e) else ERROR_WAIT
            log.error("IMAP error: %s; retrying in %ds", describe(e), wait)  # server text, addresses blanked
            wait_purging(stop, store, wait)
        except OSError as e:
            log.error("connection error: %s; retrying in %ds", describe(e), ERROR_WAIT)
            wait_purging(stop, store, ERROR_WAIT)
        finally:
            if conn is not None:
                with contextlib.suppress(imaplib.IMAP4.error, OSError):
                    conn.logout()
    log.info("poller stopped")


if __name__ == "__main__":
    main()
