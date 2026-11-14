"""Turn a Markdown answer into a PDF document."""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

INK, MUTED, RULE, ACCENT = colors.HexColor("#0f172a"), colors.HexColor("#64748b"), colors.HexColor("#e2e8f0"), colors.HexColor("#ea580c")
PAGE_WIDTH = A4[0] - 36 * mm

# The built-in PDF fonts cover Windows-1252 only. Common typography is mapped;
# anything else (emoji, CJK) is dropped rather than printed as a black box.
_REPLACE = {"→": "->", "←": "<-", "↑": "up", "↓": "down", "✓": "yes", "✗": "no", "≥": ">=", "≤": "<=", "≠": "!=", "\u00a0": " ", "\t": "    "}


def _printable(text: str) -> str:
    for src, dst in _REPLACE.items():
        text = text.replace(src, dst)
    return text.encode("cp1252", errors="ignore").decode("cp1252")


def _inline(text: str) -> str:
    """Markdown inline marks to the small markup ReportLab paragraphs accept."""
    codes: list[str] = []

    def keep_code(match: re.Match) -> str:
        codes.append(match.group(1))
        return f"\x00{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", keep_code, _printable(text))
    text = escape(text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<link href="\2" color="#c2410c">\1</link>', text)
    text = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: f"<b>{m.group(1) or m.group(2)}</b>", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", text)
    return re.sub(
        r"\x00(\d+)\x00",
        lambda m: f'<font face="Courier" size="9" color="#9a3412">{escape(codes[int(m.group(1))])}</font>',
        text,
    )


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["BodyText"]
    body = ParagraphStyle("gn-body", parent=base, fontName="Helvetica", fontSize=10, leading=14.5, textColor=INK, alignment=TA_LEFT, spaceAfter=6)
    return {
        "body": body,
        "title": ParagraphStyle("gn-title", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=25, spaceAfter=2),
        "meta": ParagraphStyle("gn-meta", parent=body, fontSize=9, textColor=MUTED, spaceAfter=10),
        "h1": ParagraphStyle("gn-h1", parent=body, fontName="Helvetica-Bold", fontSize=15, leading=19, spaceBefore=12, spaceAfter=6),
        "h2": ParagraphStyle("gn-h2", parent=body, fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("gn-h3", parent=body, fontName="Helvetica-Bold", fontSize=10.5, leading=14, spaceBefore=8, spaceAfter=3),
        "item": ParagraphStyle("gn-item", parent=body, leftIndent=18, bulletIndent=4, spaceAfter=3),
        "item2": ParagraphStyle("gn-item2", parent=body, leftIndent=34, bulletIndent=20, spaceAfter=3),
        "quote": ParagraphStyle("gn-quote", parent=body, leftIndent=10, textColor=MUTED, borderPadding=(0, 0, 0, 6)),
        "cell": ParagraphStyle("gn-cell", parent=body, fontSize=8.5, leading=11, spaceAfter=0),
        "head": ParagraphStyle("gn-head", parent=body, fontName="Helvetica-Bold", fontSize=8.5, leading=11, spaceAfter=0),
        "code": ParagraphStyle("gn-code", parent=body, fontName="Courier", fontSize=8, leading=10.5, backColor=colors.HexColor("#f1f5f9"), borderPadding=6, spaceBefore=4, spaceAfter=10),
    }


_TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_BULLET = re.compile(r"^(\s*)([-*+•])\s+(.*)$")
_NUMBER = re.compile(r"^(\s*)(\d+)[.)]\s+(.*)$")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _table(rows: list[list[str]], st: dict) -> Table:
    columns = max(len(r) for r in rows)
    rows = [r + [""] * (columns - len(r)) for r in rows]
    # Share the page width by how much text each column holds, within limits.
    weights = [max(6, min(40, max(len(r[i]) for r in rows))) for i in range(columns)]
    widths = [PAGE_WIDTH * w / sum(weights) for w in weights]
    data = [[Paragraph(_inline(c), st["head" if i == 0 else "cell"]) for c in row] for i, row in enumerate(rows)]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _flowables(markdown: str, st: dict) -> list:
    lines = markdown.replace("\r\n", "\n").split("\n")
    out: list = []
    paragraph: list[str] = []
    i = 0

    def flush() -> None:
        if paragraph:
            out.append(Paragraph(_inline(" ".join(paragraph)), st["body"]))
            paragraph.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            flush()
            block: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(_printable(lines[i])[:110])
                i += 1
            out.append(Preformatted("\n".join(block) or " ", st["code"]))
        elif not stripped:
            flush()
        elif re.fullmatch(r"(-{3,}|\*{3,}|_{3,})", stripped):
            flush()
            out.append(HRFlowable(width="100%", thickness=0.6, color=RULE, spaceBefore=6, spaceAfter=8))
        elif stripped.startswith("#"):
            flush()
            level = min(len(stripped) - len(stripped.lstrip("#")), 3)
            out.append(Paragraph(_inline(stripped.lstrip("#").strip()), st[f"h{level}"]))
        elif "|" in stripped and i + 1 < len(lines) and _TABLE_RULE.match(lines[i + 1]) and "-" in lines[i + 1]:
            flush()
            rows = [_cells(stripped)]
            i += 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                rows.append(_cells(lines[i]))
                i += 1
            out.extend([_table(rows, st), Spacer(1, 8)])
            continue
        elif _BULLET.match(line) or _NUMBER.match(line):
            flush()
            # One entry per list line: (nested?, marker, text). Indented lines
            # that are not list lines continue the entry above them.
            entries: list[list] = []
            while i < len(lines) and lines[i].strip():
                number, bullet = _NUMBER.match(lines[i]), _BULLET.match(lines[i])
                match = number or bullet
                if match:
                    nested = len(match.group(1).replace("\t", "  ")) >= 2
                    entries.append([nested, f"{number.group(2)}." if number else "•", match.group(3)])
                elif lines[i].startswith((" ", "\t")):
                    entries[-1][2] += " " + lines[i].strip()
                else:
                    break
                i += 1
            for nested, marker, text in entries:
                out.append(Paragraph(_inline(text), st["item2" if nested else "item"], bulletText=marker))
            out.append(Spacer(1, 4))
            continue
        elif stripped.startswith(">"):
            flush()
            out.append(Paragraph(_inline(stripped.lstrip("> ").strip()), st["quote"]))
        else:
            paragraph.append(stripped)
        i += 1
    flush()
    return out


def markdown_to_pdf(title: str, markdown: str, *, organization: str = "", author: str = "") -> bytes:
    """Render ``markdown`` as an A4 PDF with a title block and page numbers."""
    st = _styles()
    title = _printable(title).strip() or "Report"
    generated = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    def footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, _printable(f"GuardNous  ·  {title}")[:90])
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=title, author=_printable(author) or "GuardNous",
    )
    meta = "  ·  ".join(filter(None, [_printable(organization), f"Generated {generated}", f"by {_printable(author)}" if author else ""]))
    body = _flowables(markdown or "", st)
    # A report that opens with its own top heading equal to the title would print it twice.
    if body and isinstance(body[0], Paragraph) and body[0].getPlainText().strip().lower() == title.lower():
        body.pop(0)
    story = [
        Paragraph(escape(title), st["title"]),
        Paragraph(escape(meta), st["meta"]),
        HRFlowable(width="100%", thickness=1.2, color=ACCENT, spaceAfter=10),
        *body,
    ]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def safe_filename(title: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "-", _printable(title)).strip("-").lower()[:60] or "report"
    return f"{stem}.pdf"
