# Security

Email Health Check logs in to a mailbox, sends email and keeps short-lived reports, so security and
privacy problems matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub instead: on this repository's
**Security** tab, choose **Report a vulnerability**.

Please include what you found, how to reproduce it, and what an attacker could do with it. You'll get a
reply as soon as possible, and credit in the fix if you'd like it.

## What counts

For example:

- Getting the tool to send email to someone who didn't send a test (spam or a mail loop), or getting
  around the sending limits
- Seeing someone else's report other than by entering the address it was sent from (that lookup is
  open by design: see Privacy and limits in the documentation, at `/docs/privacy/`), or finding out who has used the tool
- Anything that stores or logs more than that page describes (message bodies,
  addresses in logs or URLs)
- A message that crashes, stalls or takes over the poller or the web page
- Ways around the web page's protections (rate limits, cross-site form posts, security headers)

Problems in the mail server, SMTP service or reverse proxy you run it with should go to those projects.

## Supported versions

Only the latest version on the `main` branch gets fixes.
