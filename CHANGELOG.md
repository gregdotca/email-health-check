# Changelog

Date-grouped, newest first.

## Unreleased

### Web page
- New settings `CUSTOM_HEADER_HTML` and `CUSTOM_HEADER_CSP`: add your own HTML to the `<head>` of every web page
  (visitor statistics and the like) and say what it may load. Inline scripts and styles are allowed by
  their hashes, the rest of the Content-Security-Policy stays as strict as before, and the code is left off
  the pages that report links open. The privacy page says when a site carries such code.
- `.env.example` now starts with the settings you must fill in, followed by every optional setting already
  set to its default.

### Documentation
- "Send an email to" in place of "Send one email to" / "Send any email to" on the introduction page
  (`services/web/project/templates/doc-pages/index.html:4`), the setup page
  (`services/web/project/templates/doc-pages/setup.html:56`) and the README (`README.md:3`).
- README: the DejaVu font license note is now its own paragraph under License.
- Documentation on the web page at `/docs/`: sending a test, viewing reports online, reading the report
  and its summary, a page per check (PTR, SPF, DKIM, DMARC) with every result and how to fix it,
  troubleshooting, privacy and limits, a glossary, and a section on running your own (how it works,
  setup, settings, logs). It fills in the installation's own test address, limits and retention times,
  and its example summaries are drawn by the same rules as real reports.
- Linked from the page header, from each box of a report ("What does this mean?") and from a closing line
  in the report emails. `/docs`, `/help` and `/documentation` redirect (301) to `/docs/`.
- New setting `DOCS_ENABLED` (default `True`): `False` removes the pages and every link to them. The web
  service is now also given `RECEIVING_EMAIL_ADDRESS` and `POLL_SECONDS` (for the documentation), never
  the mail logins.
- A "Common questions" page for the situations people run into (aliases, forwarding, subdomains, several
  mail services, DNS caching, IPv6, sharing reports, running two copies, dry runs and more), and the
  documentation covers every rule, limit, user-visible message and log message.
- Documented: use a mailbox that only gets tests (the poller checks and deletes everything in it),
  implicit SMTP TLS (port 465) isn't supported, and how to switch a running installation to email-only.
- The web page and documentation follow the system's light or dark setting (no toggle), now including the
  browser's own parts, such as scrollbars and form fields.
- The README is now short (what it is, requirements, quick start, the required settings, common
  questions): the details live in the documentation.
- A page that doesn't exist now says so (with a link to the documentation when it's on).

### Fixes (final review)
- DKIM: a signature the published key rules out (its `h=` hash list, or `t=s` with an `i=` identity at a
  subdomain) now fails. It used to pass, and could make DMARC pass too.
- Reverse DNS: only the sending IP's own address family is looked up, and a DNS error on one PTR name no
  longer hides a later name that confirms the IP.
- SPF: nothing after `all` is counted or reported, as it's never reached.
- Each message's DNS lookups share a 30-second budget (SPF keeps its own 20 seconds), so a domain with slow
  DNS can't hold up other tests.
- A refused SMTP login keeps the test and retries it, instead of deleting it unanswered.
- Expired reports are also cleared between messages in a long batch, not only between mailbox checks.
- Report emails now carry a `Date` header. Logs blank quoted addresses too, and strip line breaks.
- Report wording: no semicolons ("..., and also ...").
- `.gitignore` and `.dockerignore` cover SQLite's side files (`-wal`, `-shm`, `-journal`).

### Wording
- The SPF note for a record near its 10-lookup limit no longer says going over breaks all of a domain's
  mail (servers matched early still pass). The DKIM pass explanation no longer claims more than DKIM
  proves, and the web page's "no report was emailed" note also mentions sending limits.
- `--check-smtp` only claims the steps it took (TLS and the login are optional).
- The web page's lookup-limit message is now "Too many lookups from your network. Try again later." (the
  hourly limit can take up to an hour to clear, so "Wait a minute" was misleading).
- README: the SMTP login is optional, an empty `SENDING_EMAIL_FROM_NAME` means no name, retries are
  minimum gaps on later mailbox checks, and the limits are rolling windows.

## 2026-10-04: first public release

### Checks
- Finds the `Received:` header written by the receiving mail server (`TRUSTED_MX_HOSTS`, Exim's
  format) and takes the connecting IP, HELO and envelope sender from it. Nothing below that header is
  trusted. A backup MX relaying to the main one is recognised by verified reverse DNS, never by HELO.
- PTR: reverse DNS for the sending IP, checked forward again (iprev).
- SPF (RFC 7208, via pyspf): the result, the record, and problems such as more than 10 DNS lookups,
  void lookups or oversized records, with time and lookup limits so a hostile record can't stall it.
- DKIM (via dkimpy): every signature up to 5, verified, with expired signatures and broken keys
  explained. `rsa-sha1` signatures never count as a pass (RFC 8301). Limits on what one signature can
  cost (header fields listed, header fields in the message, key size), and a malformed signature only
  fails itself, never the rest of the report.
- Only what the report shows is worked out and kept (no display names, TLS details or other extras).
- DMARC: the result, the policy, SPF and DKIM alignment (relaxed or strict), and "Problem:" notes for
  invalid records.
- MX records, for "Can receive email".
- A warning when a message was submitted by logging in to the receiving server itself, since the checks
  then don't show what other receivers would see.
- Encoded subjects (RFC 2047) are decoded, and sender-controlled text is length-limited and escaped.

### Report
- A summary box first: Can send email, Can receive email, Is authenticated, with an "All Tests Passed",
  "Needs Attention" or "Incomplete" badge, then the message summary and one box per check.
  Explanations only for checks that don't pass.
- The results email has plain-text and HTML parts with the same details, the summary drawn as a PNG
  (Pillow, bundled DejaVu fonts) and the full headers attached as a text file.
- Sent to the From: address when the envelope sender is at the same domain. Failing SPF, DKIM or DMARC
  never stops a reply. Bounces, auto-replies, mailing lists, no-reply addresses and the tool's own
  domain are never answered.
- Times are shown in `DISPLAY_TIMEZONE`.

### Web page (optional)
- Look up the latest report by the address you sent from. Each results email links to a random
  128-bit token instead of an address. Opening the link shows only a "View Report" button, so mail
  link scanners don't count as a view.
- A report is kept for up to 24 hours if nobody looks it up, then deleted 5 minutes after the page first
  shows it. Showing one deletes older ones for that address.
- No third-party assets or JavaScript, strict security headers, `X-Robots-Tag: noindex` and a
  `robots.txt` that disallows all crawlers. Forms posted from other sites are refused.
- Without `PUBLIC_URL` it runs email-only: no link in the emails and no reports kept.

### Mail handling and limits
- Polls INBOX and any Junk/Spam folder over IMAP (TLS) every `POLL_SECONDS`, and deletes each message
  once it's handled. Message bodies are only used in memory, for DKIM.
- Messages over 1 MB are deleted without a reply.
- Reports per recipient (5 an hour, 10 a day) and in total (50 a day), and web lookups per IP (10 a
  minute, 60 an hour), all configurable. Counters are salted hashes, kept a day.
- A temporary sending failure is retried after 1, 2, 5, 10 and 20 minutes, then given up. Retries don't
  count against the limits.
- Logs carry counts and reasons, never addresses or message content.
- `DRY_RUN=True` changes nothing: no email is sent and nothing is deleted.
- A temporary database or sending problem keeps the test in the mailbox and retries it (up to six
  attempts) before giving up.
  When a report ends up not being emailed (a limit, a failure), the web page stops saying it was.
- `python -m healthcheck.poller --check-smtp` tests the sending settings without sending anything.

### Setup
- One Docker image, two Compose services (`poller` and the optional `web`) sharing a SQLite volume.
- Every setting comes from `.env`, and `.env.example` lists them all. The web service is given only the app
  settings, never the mail passwords. A missing or invalid setting stops the service at startup
  (on/off settings take only `True` or `False`, so a typo can't turn TLS off).
- Every Python package (direct and indirect), pip and the base image are pinned to exact versions, and
  the image installs only those.
- `docker-compose.yml` never needs editing: the web page is a Compose profile switched on by
  `COMPOSE_PROFILES=web`, and the port (`WEB_BIND`) and container names (`CONTAINER_NAME`) come from
  `.env`. Host-specific Docker changes go in an ignored `docker-compose.override.yml`.
