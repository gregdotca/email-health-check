# Changelog

Date-grouped, newest first.

## Unreleased

### Fresh DNS lookups
- Every check now asks each domain's own (authoritative) DNS servers directly (`services/web/healthcheck/dnsutil.py`,
  with `spfcheck.py` sending pyspf's lookups the same way). Before, lookups went through the host's resolver,
  which keeps each answer until its TTL runs out, so a test sent just after fixing a record could still be
  checked against the old one. Only finding a domain's DNS servers still goes through the host's resolver, as
  they rarely change. If those servers don't answer in time, the lookup falls back to the host's resolver. After
  three such failures in a row, if the root DNS servers can't be reached either, lookups use only the host's
  resolver for 10 minutes, so a host that can't reach outside DNS servers doesn't slow down every test, while one
  domain with broken DNS servers can't switch fresh lookups off for everyone else. Only DNS servers at public
  addresses are asked, so a domain can't point its DNS servers at a private, loopback, or multicast address and have the
  checks send queries into the network they run in.
- The documentation (FAQ, glossary, troubleshooting, and how it works) now says the check usually sees DNS
  changes right away, while other mail servers may keep using the old record until its TTL has passed. "How it
  works" also says the checks see the public DNS records, so a local DNS override on the host (split-horizon
  DNS) usually doesn't change the result (it still can when a lookup falls back to the host's resolver).

### License
- `LICENSE`: the copyright line now includes a contact address.

### Dependency updates
- Python 3.14.8 to 3.15.2 in both stages of `services/web/Dockerfile` (Dependabot pull request #3 proposed
  3.15.0). 3.15.2 is a security release: it stops trusting the compromised eMudhra certificate authority keys
  for TLS connections, such as the ones to the mail servers, and includes the security fixes from 3.15.1. Every
  pinned package installs on 3.15, the image builds, the tests pass, and the summary image is unchanged.
- publicsuffixlist 1.0.2.20261003 to 1.1.2.20261023 and pycparser 3.0 to 3.12 in
  `services/web/requirements.txt` (Dependabot pull request #7). The newer public suffix list keeps the DMARC
  check's organizational domains current. The one function used here is unchanged, and the tests pass.
- dnspython 2.8.0 to 2.9.0 in `services/web/requirements.txt`. 2.9.0 limits how far a DNS name can be
  decompressed, so a crafted DNS answer can no longer make lookups use too much CPU. None of its changes touch
  the parts this project uses, and the tests and live DNS lookups work on it.
- Pillow 12.3.0 to 13.0.0 in `services/web/requirements.txt`, fixing the security issues reported in 12.3.0
  (Dependabot pull request #2). None of Pillow 13's breaking changes touch the parts this project uses, the
  tests pass, and the summary image comes out exactly the same.
- Python 3.13.16 to 3.14.8 in both stages of `services/web/Dockerfile`. Dependabot proposed 3.14.7, but 3.14.8
  is a security release and was already out. Every pinned package builds on 3.14 and the tests pass on it.
- Dependabot now checks `services/web/requirements.txt` and the Python base image in `services/web/Dockerfile`
  once a month (`.github/dependabot.yml`), with all pip updates grouped into one pull request. Alerts and
  security fix pull requests (set in the GitHub repository's settings) only cover known vulnerabilities, so
  nothing kept the pinned packages or the base image current otherwise. It only proposes versions that have
  been out for at least 7 days, so a bad or hijacked release has time to be caught and pulled first. Security
  fixes aren't delayed. `requirements.txt` pins every package, indirect ones included, and the image installs
  only those, so an update that needs a new indirect package fails the build until it's added. Not covered,
  so still updated by hand: pip, setuptools, flake8 and its checkers (mccabe, pycodestyle, pyflakes), all
  pinned in the `Dockerfile`.

### Web page
- The homepage can now say how to send a test: the test address, how soon the report arrives, how to view
  the report with the form below, and where to find the documentation.
- New setting `IS_PUBLIC_INSTANCE` (default `False`): `True` shows that text and lets the documentation name
  the test address, how often it's checked, the address the reports come from and the time zone, for a
  website meant for anyone. On such a site the documentation says which address reports come from (look for
  it in spam, add it to your contacts). The web service is now also given `SENDING_EMAIL_FROM` and
  `SENDING_EMAIL_FROM_NAME` for this. It's the first setting in `.env.example`.
- `SENDING_EMAIL_FROM` and `SENDING_EMAIL_FROM_NAME` made of only spaces now count as empty (the test address,
  and no display name), where a space-only address used to make a broken From: line. With `False` the home page is
  just the form, and the documentation says "the test address" without naming it (with a line saying to
  ask whoever runs the site). A report's full email headers, viewed online, still include it.
- The Docs link in the page header stands out more: an outlined button in the accent colour.
- New settings `CUSTOM_HEADER_HTML` and `CUSTOM_HEADER_CSP`: add your own HTML to the `<head>` of every web page
  (visitor statistics and the like) and say what it may load. Inline scripts and styles are allowed by
  their hashes, the rest of the Content-Security-Policy stays as strict as before, and the code is left off
  the pages that report links open. The privacy page says when a site carries such code.
- `.env.example` now starts with the settings you must fill in, followed by every optional setting already
  set to its default.

### Documentation
- Search: a search box at the top of the documentation's sidebar (above the page on phones) shows results as
  you type, with the matching words highlighted. Press `/` to jump to it, the arrow keys to pick a
  result, and Enter to open it (or the full list of results). It searches in the browser with a small script
  of the website's own, allowed on the documentation's pages only. Without JavaScript the box still works:
  Enter opens a results page listing every match. Email addresses aren't searched. Highlighted words stay
  readable in dark mode, long words wrap on phones, and a page that fails to load is left out of the search
  rather than breaking it.
- README brought in line with the documentation: the first report arrives "within a minute or so" (was
  "about 30 seconds"), the docs name the test address only with `IS_PUBLIC_INSTANCE=True`, the first section
  of `.env.example` starts with `IS_PUBLIC_INSTANCE`, retention times are the defaults, and SMTP may run
  without TLS (implicit TLS on port 465 isn't supported).
- Requirements (README and setup page): the test mailbox and the Exim-style mail server are now one item,
  since the mailbox lives on that server.
- "What's in the report" names the report emails' real sender (`SENDING_EMAIL_FROM_NAME`), where it always
  said `APP_NAME`.
- Sample domains are now `example.com` throughout (was `yourdomain.com` in places, and `example.net` for the
  sample mail servers in `.env.example`), with `example.org` where a second domain is needed (a mail
  service's own domain, `mailservice.example.org`). Only domains reserved for examples are used, so the
  glossary no longer names a real registered domain.
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
- Documentation: the introduction and "Send a test" now say the same thing about what to send: "Any subject
  and any body text will do (don't leave them blank)."
- `ACR.md`: the "How AI Was Used" section now says the code is also reviewed by a second AI, which it
  already was, and has a comma before "and the documentation". `updated` is 2026-10-09.
- The AI Code Rating is now `B4b` (Oversight: Reviewed, was Spot-Checked): every AI change is read by the
  maintainer before it's committed. `ACR.md` and the README badge say so, and `updated` is 2026-10-12.

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
