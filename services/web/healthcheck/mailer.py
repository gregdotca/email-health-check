"""Email the results back to the address that sent the test message (SMTP).

A reply goes to the From: address when the envelope sender is at the same domain (by
organizational domain, so bounce.example.com matches example.com). Authentication results don't
decide it: a failing setup is exactly what a sender wants to hear about. Both addresses are easy
to forge, so per-recipient and daily caps (store.MAIL_LIMITS) limit misuse. Bounces,
auto-replies, mailing lists and anything aimed back at this tool are never answered, so two
auto-responders can't loop.
"""
import email
import email.policy
import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

import jinja2

from . import report, summary_image
from .analyze import automatic_reason
from .dmarccheck import aligned
from .settings import settings
from .store import UNVIEWED_SECONDS, VIEWED_SECONDS

log = logging.getLogger("healthcheck.mailer")

DEFAULT_FROM_NAME = settings.app_name  # APP_NAME, unless SENDING_EMAIL_FROM_NAME says otherwise


def report_sender(env, test_address):
    """The report emails' From: address and display name, from SENDING_EMAIL_FROM (default: the test address)
    and SENDING_EMAIL_FROM_NAME (unset: APP_NAME, empty: no name). Spaces around either are ignored, so a value
    of only spaces counts as empty. The poller sends with these, and the docs describe them, so both agree."""
    address = (env.get("SENDING_EMAIL_FROM") or "").strip() or test_address
    return address, env.get("SENDING_EMAIL_FROM_NAME", DEFAULT_FROM_NAME).strip()
RESULTS_URL = settings.public_url  # PUBLIC_URL: the web page where the same results can be looked up ("": none)


def results_link(r):
    """This result's own web page, <PUBLIC_URL>/<random token> (it shows a "View
    Report" button, so a link scanner opening it doesn't count as a view). Just the site if it wasn't
    saved, and "" if there's no web page."""
    if not RESULTS_URL:
        return ""
    return f"{RESULTS_URL}/{r['token']}" if r.get("token") else RESULTS_URL


def web_note(r):
    """The closing line pointing to the web page, with the real retention times ("" without one)."""
    if not RESULTS_URL:
        return ""
    return (f"You can also view this report at {results_link(r)} for up to {UNVIEWED_SECONDS // 3600} hours. "
            f"The online copy is deleted {VIEWED_SECONDS // 60} minutes after the first time it's viewed.")


def docs_link():
    """The documentation's page about reading the report ("" without a web page or with DOCS_ENABLED=False)."""
    return f"{RESULTS_URL}/docs/the-report/" if RESULTS_URL and settings.docs_enabled else ""


def docs_note():
    """The closing line pointing to the documentation ("" without it)."""
    return f"What the report means, check by check: {docs_link()}" if docs_link() else ""


# postmaster@ is answered on purpose (it's a common address to test from); real bounces are still caught by the
# empty envelope sender and Auto-Submitted checks
SKIP_LOCAL_PARTS = {"mailer-daemon", "noreply", "no-reply", "donotreply", "do-not-reply"}
# A Message-ID is only reused for threading if it looks ordinary: a crafted one (e.g. thousands of
# nested comments) can make Python's header code recurse until it crashes.
PLAIN_MESSAGE_ID = re.compile(r"<[^<>()\s@]{1,200}@[^<>()\s@]{1,200}>")


def reply_to(result, own_addresses=(), own_domain=None):
    """(recipient, None) if a results email should go out, else (None, reason).

    own_addresses: this tool's mailbox and sending address; own_domain: the mailbox's domain.
    """
    if result.get("error"):
        return None, "not analysed"
    to = (result.get("from") or "").lower()
    if "@" not in to:
        return None, "no single From: address"
    local, _, domain = to.rpartition("@")
    if to in {a.lower() for a in own_addresses if a} or (own_domain and domain == own_domain.lower()):
        return None, "addressed to this tool"
    if local in SKIP_LOCAL_PARTS:
        return None, "system or no-reply address"
    envelope = (result.get("envelope_from") or "").lower()
    if not envelope:
        return None, "bounce (empty envelope sender)"
    if not aligned(envelope.rpartition("@")[2], domain, "r"):
        return None, "envelope sender is at a different domain"

    if "automatic" in result:  # decided during analysis, on the full (not cut-off) headers
        reason = result["automatic"]
    else:  # a result saved before that field existed: judge from the stored headers
        reason = automatic_reason(email.message_from_string(result.get("headers", ""),
                                                            policy=email.policy.compat32))
    if reason:
        return None, reason
    return to, None


sender_domain = report.sender_domain  # the domain being tested: the From: address's domain


def render_text(r):
    """The plain-text results email: the same details, in the same order, as the HTML part
    (templates/email.html): change the two together."""
    hop = r.get("hop") or {}
    spf, dmarc = r.get("spf"), r.get("dmarc")
    lines = [settings.app_name, sender_domain(r), ""]
    lines.append(f"{sender_domain(r)}: {report.overview_status(r)}")
    for passed, label, detail in report.overview(r):
        lines.append(f"  {report.mark(passed)} {label + ':':<19}   {detail}")
    lines.append("")
    lines += [f"Subject:       {r.get('subject') or '(no subject)'}",
              f"Date Received: {report.received(r)}",
              f"From Address:  {r.get('from') or '(none)'}"]
    if hop.get("ip"):
        lines.append(f"Sending IP:    {hop['ip']}" + (f" ({hop['rdns']})" if hop.get("rdns") else ""))
    lines.append("")
    for w in r.get("warnings") or []:
        lines += [f"Note: {w}", ""]
    lines += [f"PTR:   {report.ptr_status(r)}",
              f"SPF:   {spf['result'] if spf else 'not checked'}",
              f"DKIM:  {report.dkim_summary(r.get('dkim'))}",
              f"DMARC: {dmarc['result'] if dmarc else 'not checked'}", ""]

    lines.append(f"PTR: {report.ptr_status(r)}")
    if report.ptr_status(r) != "pass":
        lines.append(f"  {report.ptr_explanation(r)}")
    for label, value in report.ptr_rows(r):
        lines.append(f"  {label + ':':<13} {value}")
    lines.append("")

    lines.append(f"SPF: {spf['result'] if spf else 'not checked'}")
    if spf:
        if spf["result"] != "pass":
            lines.append(f"  {spf['explanation']}")
        for note in spf.get("notes") or []:
            lines.append(f"  Problem: {note}")
        lines.append(f"  Checked:     {spf['domain']}")
        lines.append(f"  Sending IP:  {hop.get('ip')}")
        if spf.get("record"):
            lines.append(f"  Record:      {spf['record']}")
        if report.spf_lookups(spf):
            lines.append(f"  DNS lookups: {report.spf_lookups(spf)}")
        if spf["result"] not in ("pass", "none"):
            lines.append(f"  Detail:      {spf['detail']}")
    else:
        lines.append("  Not checked: the sending server couldn't be identified.")
    lines.append("")

    lines.append(f"DKIM: {report.dkim_summary(r.get('dkim'))}")
    if not r.get("dkim"):
        lines.append("  The message has no DKIM signature.")
    for s in r.get("dkim") or []:
        lines.append(f"  {s['result']}: signed by {s['domain']}")
        if s["result"] != "pass":
            lines.append(f"    {s['explanation']}")
        lines.append(f"    Selector:  {s['selector']}._domainkey.{s['domain']}")
        if s.get("reason") and s["result"] != "pass":
            lines.append(f"    Reason:    {s['reason']}")
    lines.append("")

    lines.append(f"DMARC: {dmarc['result'] if dmarc else 'not checked'}")
    if dmarc:
        if dmarc["result"] != "pass":
            lines.append(f"  {dmarc['explanation']}")
        for note in dmarc.get("notes") or []:
            lines.append(f"  Problem: {note}")
        if dmarc.get("record"):
            lines.append(f"  Record:       _dmarc.{dmarc['record_domain']}: {dmarc['record']}")
            lines.append(f"  Policy:       {dmarc['policy']}")
        lines.append(f"  SPF aligned:  {'yes' if dmarc['spf_aligned'] else 'no'}")
        lines.append(f"  DKIM aligned: {'yes' if dmarc['dkim_aligned'] else 'no'}")
    else:
        lines.append("  Not checked: the message needs exactly one From: address.")
    if web_note(r):
        lines += ["", web_note(r)]
    if docs_note():
        lines += ["", docs_note()]
    return "\n".join(lines) + "\n"


_jinja = jinja2.Environment(loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
                            autoescape=True, trim_blocks=True, lstrip_blocks=True)
for _name in ("verdict", "ptr_status", "ptr_rows", "ptr_explanation", "spf_lookups", "dkim_summary", "overview",
              "overview_status", "mark", "mark_verdict"):
    _jinja.filters[_name] = getattr(report, _name)


def render_html(r, subject):
    """The HTML part: an overview box, a summary box and one box per check, in email-safe markup."""
    return _jinja.get_template("email.html").render(
        r=r, heading=settings.app_name, domain=sender_domain(r), subject=subject, when=report.received(r),
        results_url=results_link(r), docs_url=docs_link(),
        unviewed_hours=UNVIEWED_SECONDS // 3600, viewed_minutes=VIEWED_SECONDS // 60)


def subject_for(r):
    """`Report for <sending domain>` (the Email Health Check Report)."""
    return f"Report for {sender_domain(r)}"


def build_message(r, to, from_addr, from_name=DEFAULT_FROM_NAME):
    """multipart/mixed: [multipart/alternative: text, HTML], then the overview box as a PNG and the
    headers as attachments."""
    subject = subject_for(r)
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_addr)) if from_name else from_addr
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(usegmt=True)  # required (RFC 5322), and not every relay adds one
    msg["Message-ID"] = make_msgid(domain=from_addr.rpartition("@")[2] or None)
    message_id = (r.get("message_id") or "").strip()
    if PLAIN_MESSAGE_ID.fullmatch(message_id):
        msg["In-Reply-To"] = message_id
        msg["References"] = message_id
    # RFC 3834: this is an automatic reply, so other auto-responders mustn't answer it
    msg["Auto-Submitted"] = "auto-replied"
    msg["X-Auto-Response-Suppress"] = "All"
    msg.set_content(render_text(r))
    msg.add_alternative(render_html(r, subject), subtype="html")
    try:  # the overview box as an image, for sharing; never worth losing the email over
        msg.add_attachment(summary_image.render_png(r), maintype="image", subtype="png",
                           filename=summary_image.filename(r))
    except Exception as e:
        log.error("drawing the summary image failed (%s); sending without it", type(e).__name__)
    msg.add_attachment(r.get("headers", "").encode("utf-8"), maintype="text", subtype="plain",
                       filename=report.headers_filename(r))
    return msg


class SendError(Exception):
    """A send that failed, with the step it failed at. The message never contains addresses."""

    def __init__(self, stage, error):
        self.stage, self.error = stage, error
        super().__init__(f"{stage}: {describe(error)}")

    @property
    def temporary(self):
        """Worth trying again: a dropped or refused connection, a timeout, a 4xx reply, or a refused login
        (the SMTP settings or the service are at fault, not the test: keep it rather than lose it)."""
        e = self.error
        if self.stage == "logging in":
            return True
        if isinstance(e, smtplib.SMTPRecipientsRefused):
            return all(400 <= code < 500 for code, _ in e.recipients.values())
        if isinstance(e, smtplib.SMTPResponseException):
            return 400 <= e.smtp_code < 500
        return isinstance(e, (smtplib.SMTPServerDisconnected, OSError))


def describe(error):
    """An SMTP/socket error as text, with any email addresses blanked out (logs carry no addresses)."""
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        text = "recipient refused: " + ", ".join(f"{code} {msg.decode(errors='replace')}"
                                                 for code, msg in error.recipients.values())
    elif isinstance(error, smtplib.SMTPResponseException):
        msg = error.smtp_error
        text = f"{error.smtp_code} {msg.decode(errors='replace') if isinstance(msg, bytes) else msg}"
    else:
        text = f"{type(error).__name__}: {error}"
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)  # server text: no line breaks or control characters in the log
    text = re.sub(r'<?"(?:[^"\\]|\\.)*"@[^\s<>]+>?', "<address>", text)  # a quoted local part (spaces, \" escapes)
    return re.sub(r"<?[^\s<>@]+@[^\s<>]+>?", "<address>", text)


class Mailer:
    def __init__(self, host, port, use_tls, user, password, from_addr, from_name=DEFAULT_FROM_NAME):
        self.host, self.port, self.use_tls = host, port, use_tls
        self.user, self.password = user, password
        self.from_addr, self.from_name = from_addr, from_name

    def _session(self, smtp_steps):
        """Connect, STARTTLS and log in, then run smtp_steps(smtp). Raises SendError naming the step.

        Once smtp_steps has finished, the email has been accepted: an error while saying goodbye
        (QUIT) is only logged, so the poller doesn't send the same results twice.
        """
        stage = f"connecting to {self.host}:{self.port}"
        try:
            with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
                if self.use_tls:
                    stage = "starting TLS (STARTTLS)"
                    # an explicit context: smtplib's default doesn't check the certificate
                    smtp.starttls(context=ssl.create_default_context())
                if self.user:
                    stage = "logging in"
                    smtp.login(self.user, self.password)
                stage = "sending"
                smtp_steps(smtp)
                stage = "closing the connection"
        except (smtplib.SMTPException, OSError) as e:
            if stage == "closing the connection":
                log.warning("the email was accepted, but closing the connection failed: %s", describe(e))
                return
            raise SendError(stage, e) from e

    def send(self, r, to):
        msg = build_message(r, to, self.from_addr, self.from_name)
        self._session(lambda smtp: smtp.send_message(msg))

    def check(self):
        """Connect, STARTTLS and log in without sending anything. Raises SendError on failure."""
        self._session(lambda smtp: smtp.noop())
