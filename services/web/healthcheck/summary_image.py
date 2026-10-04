"""The overview box as a PNG, attached to the results email so it can be shared (a ticket, a chat).

Drawn with Pillow from report.overview(), the same rows as the text and HTML emails, in the HTML
email's colours (templates/email.html); keep the two looking alike. The fonts are bundled (DejaVu,
fonts/LICENSE-DejaVu.txt) so the image doesn't depend on what the container has installed.
"""
import io
import re
from functools import cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from . import report
from .settings import settings

FONTS = Path(__file__).parent / "fonts"
SCALE = 2  # drawn at 2x, so it stays sharp on high-resolution screens

# the HTML email's colours: (text, background) per verdict, and the page's
COLOURS = {"good": ("#1a7f37", "#dafbe1"), "bad": ("#b42318", "#fde4e1"),
           "warn": ("#8a5300", "#fff3cd"), "neutral": ("#57606a", "#eaeef2")}
PAGE, CARD, BORDER, TEXT, MUTED = "#f6f6f4", "#ffffff", "#e2e2dc", "#1f2328", "#5d6166"

# sizes in CSS pixels (multiplied by SCALE when drawn)
WIDTH, MARGIN, PADDING, RADIUS = 640, 16, 20, 12
TITLE_SIZE, BADGE_SIZE, ROW_SIZE, DOMAIN_SIZE = 16, 12, 14, 14
SLANT = 0.2  # the date's italic: DejaVu has no italic face bundled, and its oblique is this same slant
LINE = 1.5  # line height, as in the email
MARK_WIDTH, LABEL_GAP = 24, 32
MAX_DOMAIN, MAX_DETAIL = 255, 400  # characters shown (a real domain is at most 253)


@cache
def font(size, bold=False):
    return ImageFont.truetype(str(FONTS / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")), size * SCALE)


def shorten(text, limit):
    """At most limit characters, "…" marking a cut: what a sender controls (a From: domain can be ~2,000
    characters) mustn't make the image huge or slow to draw."""
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


def wrap(text, face, width):
    """Lines of text no wider than width; a single word that is too long (a long domain) is broken after
    a dot or hyphen where possible, else between characters."""
    lines, line = [], ""
    for word in text.split():
        candidate = f"{line} {word}" if line else word
        if face.getlength(candidate) <= width:
            line = candidate
            continue
        if line:
            lines.append(line)
        while face.getlength(word) > width:  # e.g. a very long domain name
            lo, hi = 1, len(word)  # binary search for the longest start that fits: a few measurements
            while lo < hi:
                mid = (lo + hi + 1) // 2
                lo, hi = (mid, hi) if face.getlength(word[:mid]) <= width else (lo, mid - 1)
            cut = max((i + 1 for i in range(lo) if word[i] in ".-"), default=lo)
            lines.append(word[:cut])
            word = word[cut:]
        line = word
    return lines + [line] if line else lines or [""]


def header_parts(r):
    """The picture's title: the tool's name (bold), " - ", when the test arrived (italic)."""
    return settings.app_name, " - ", report.received(r)


def draw_italic(img, xy, text, face, fill):
    """Draw text slanted to the right (an oblique), returning its width."""
    left, top, right, bottom = face.getbbox(text)
    width, height = int(right) + 2, int(bottom) + 2
    extra = int(height * SLANT) + 2
    mask = Image.new("L", (width + extra, height), 0)
    ImageDraw.Draw(mask).text((extra, 0), text, font=face, fill=255)
    # shear: the top of each letter moves right, the baseline stays put
    mask = mask.transform(mask.size, Image.Transform.AFFINE, (1, SLANT, -SLANT * height, 0, 1, 0),
                          resample=Image.Resampling.BICUBIC)
    img.paste(fill, (xy[0] - extra, xy[1]), mask)  # the baseline lands exactly at xy
    return face.getlength(text)


def render_png(r):
    """The overview box as PNG bytes: a title (the tool's name and when the test arrived), then the domain
    and its badge, then the three rows (the email's version)."""
    s = SCALE
    rows = report.overview(r)
    status = report.overview_status(r)
    domain = shorten(report.sender_domain(r), MAX_DOMAIN)
    name, separator, when = header_parts(r)

    title_bold, title_font = font(TITLE_SIZE, True), font(TITLE_SIZE)
    domain_font, badge_font = font(DOMAIN_SIZE, True), font(BADGE_SIZE, True)
    row_font, mark_font = font(ROW_SIZE), font(ROW_SIZE, True)
    inner = (WIDTH - 2 * PADDING) * s
    label_width = max(row_font.getlength(label) for _, label, _ in rows)
    detail_x = MARK_WIDTH * s + label_width + LABEL_GAP * s
    row_line = round(ROW_SIZE * LINE * s)

    # the title on one line if it fits, else the date on a line of its own
    title_line = round(TITLE_SIZE * LINE * s)
    title_w = title_bold.getlength(name) + title_font.getlength(separator) + title_font.getlength(when)
    title_one_line = title_w <= inner
    title_h = title_line * (1 if title_one_line else 2)

    # the domain, with the badge beside it if it fits, else on its own line
    badge_text_w = badge_font.getlength(status)
    badge_w, badge_h = badge_text_w + 18 * s, round(BADGE_SIZE * 1.6 * s)
    domain_lines = wrap(domain, domain_font, inner)
    domain_line = max(round(DOMAIN_SIZE * LINE * s), badge_h)
    badge_inline = domain_font.getlength(domain_lines[-1]) + 10 * s + badge_w <= inner
    domain_h = domain_line * len(domain_lines) + (0 if badge_inline else badge_h + 8 * s)

    # the email's notes aren't in the image, so don't point to them
    wrapped = [wrap(shorten(re.sub(r" \(see (?:the note )?below\)", "", detail), MAX_DETAIL), row_font,
                    inner - detail_x) for _, _, detail in rows]
    rows_h = sum(row_line * len(lines) for lines in wrapped) + 4 * s * (len(rows) - 1)
    card_h = PADDING * s * 2 + title_h + 8 * s + domain_h + 18 * s + rows_h

    img = Image.new("RGB", (WIDTH * s + 2 * MARGIN * s, card_h + 2 * MARGIN * s), PAGE)
    draw = ImageDraw.Draw(img)
    left, top = MARGIN * s, MARGIN * s
    draw.rounded_rectangle((left, top, left + WIDTH * s - 1, top + card_h - 1), RADIUS * s, fill=CARD,
                           outline=BORDER, width=s)
    x, y = left + PADDING * s, top + PADDING * s

    draw.text((x, y), name, font=title_bold, fill=TEXT)
    if title_one_line:
        hx = x + title_bold.getlength(name)
        draw.text((hx, y), separator, font=title_font, fill=MUTED)
        draw_italic(img, (int(hx + title_font.getlength(separator)), y), when, title_font, MUTED)
    else:
        draw_italic(img, (x, y + title_line), when, title_font, MUTED)
    y += title_h + 8 * s

    for line in domain_lines:
        draw.text((x, y + (domain_line - round(DOMAIN_SIZE * LINE * s)) // 2), line, font=domain_font, fill=TEXT)
        y += domain_line
    fg, bg = COLOURS[report.verdict(status)]
    if badge_inline:
        bx, by = x + domain_font.getlength(domain_lines[-1]) + 10 * s, y - domain_line + (domain_line - badge_h) // 2
    else:
        bx, by = x, y + 8 * s
        y += badge_h + 8 * s
    draw.rounded_rectangle((bx, by, bx + badge_w, by + badge_h), badge_h // 2, fill=bg)
    draw.text((bx + badge_w / 2, by + badge_h / 2), status, font=badge_font, fill=fg, anchor="mm")
    y += 18 * s

    for (passed, label, _), lines in zip(rows, wrapped, strict=True):
        draw.text((x, y), report.mark(passed), font=mark_font, fill=COLOURS[report.mark_verdict(passed)][0])
        draw.text((x + MARK_WIDTH * s, y), label, font=row_font, fill=TEXT)
        for line in lines:
            draw.text((x + detail_x, y), line, font=row_font, fill=MUTED)
            y += row_line
        y += 4 * s

    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def filename(r):
    """`<APP_NAME> Summary (<sending domain>).png`, named like the headers attachment."""
    return report.headers_filename(r).replace("Email Headers", f"{settings.app_name} Summary").replace(".txt", ".png")
