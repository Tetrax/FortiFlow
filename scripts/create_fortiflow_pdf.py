#!/usr/bin/env python3
"""Génère le PDF du tutoriel FortiFlow à partir de TUTORIEL.md."""

import re
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, PageBreak,
)

# ── Chemins ──────────────────────────────────────────────────────────
MD_PATH = "/opt/data/FortiFlow/docs/TUTORIEL.md"
OUT = "/opt/data/FortiFlow/docs/fortiflow-tutoriel.pdf"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

pdfmetrics.registerFont(TTFont("DejaVu", FONT))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", FONT_BOLD))
pdfmetrics.registerFont(TTFont("DejaVuMono", FONT_MONO))

# ── Couleurs ─────────────────────────────────────────────────────────
NAVY = colors.HexColor("#0F2747")
BLUE = colors.HexColor("#1976D2")
LIGHT_BLUE = colors.HexColor("#EAF3FF")
LIGHT_GREEN = colors.HexColor("#EAF8F1")
ORANGE = colors.HexColor("#FFF3E0")
GRAY = colors.HexColor("#52606D")
BORDER = colors.HexColor("#D9E2EC")
DARK_TEXT = colors.HexColor("#263238")
CODE_BG = colors.HexColor("#F4F7FA")
CODE_TEXT = colors.HexColor("#13293D")

# ── Styles ───────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="CoverTitle", parent=styles["Title"],
    fontName="DejaVu-Bold", fontSize=22, leading=29,
    textColor=NAVY, alignment=TA_CENTER, spaceAfter=10,
))
styles.add(ParagraphStyle(
    name="Subtitle", parent=styles["Normal"],
    fontName="DejaVu", fontSize=10, leading=15,
    textColor=GRAY, alignment=TA_CENTER, spaceAfter=16,
))
styles.add(ParagraphStyle(
    name="H1x", parent=styles["Heading1"],
    fontName="DejaVu-Bold", fontSize=16, leading=21,
    textColor=NAVY, spaceBefore=18, spaceAfter=8,
))
styles.add(ParagraphStyle(
    name="H2x", parent=styles["Heading2"],
    fontName="DejaVu-Bold", fontSize=12, leading=16,
    textColor=BLUE, spaceBefore=12, spaceAfter=5,
))
styles.add(ParagraphStyle(
    name="Bodyx", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=9.4, leading=14,
    textColor=DARK_TEXT, spaceAfter=6,
))
styles.add(ParagraphStyle(
    name="Codex", parent=styles["Code"],
    fontName="DejaVuMono", fontSize=7.8, leading=11,
    textColor=CODE_TEXT,
))
styles.add(ParagraphStyle(
    name="TableHead", parent=styles["BodyText"],
    fontName="DejaVu-Bold", fontSize=9, leading=12,
    textColor=colors.white,
))
styles.add(ParagraphStyle(
    name="Bulletx", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=9.2, leading=13,
    leftIndent=13, firstLineIndent=-10, spaceAfter=3,
))
styles.add(ParagraphStyle(
    name="Small", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=8, leading=11, textColor=GRAY,
))

# ── Helpers ──────────────────────────────────────────────────────────

def p(text, style="Bodyx"):
    return Paragraph(text, styles[style])


def code_block(text):
    """Bloc de code avec fond gris et bordure."""
    text = sanitize_unicode(text)
    # Échapper HTML
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Remplacer les sauts de ligne par <br/>
    escaped = escaped.replace("\n", "<br/>")
    table = Table([[Paragraph(escaped, styles["Codex"])]], colWidths=[17.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def callout(title, body, background=LIGHT_BLUE):
    table = Table([[p(f"<b>{title}</b><br/>{body}", "Bodyx")]], colWidths=[17.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def bullet(text):
    return p("•  " + text, "Bulletx")


def numbered_bullet(num, text):
    return p(f"{num}.  {text}", "Bulletx")


def make_table(headers, rows):
    """Crée un tableau avec en-tête bleu marine."""
    head_row = [p(h, "TableHead") for h in headers]
    data_rows = [[p(cell, "Bodyx") for cell in row] for row in rows]
    data = [head_row] + data_rows

    # Largeur dynamique
    ncols = len(headers)
    col_width = 17.2 * cm / ncols

    t = Table(data, colWidths=[col_width] * ncols, repeatRows=1)
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    # Rayures alternées pour les lignes de données
    for i in range(1, len(data)):
        if i % 2 == 0:
            tbl_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFBFC")))
        else:
            tbl_style.append(("BACKGROUND", (0, i), (-1, i), colors.white))
    t.setStyle(TableStyle(tbl_style))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.line(1.4 * cm, 1.25 * cm, 19.6 * cm, 1.25 * cm)
    canvas.setFont("DejaVu", 7.5)
    canvas.setFillColor(GRAY)
    canvas.drawString(1.4 * cm, 0.8 * cm, "FortiFlow — Guide complet")
    canvas.drawRightString(19.6 * cm, 0.8 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Parser Markdown ──────────────────────────────────────────────────

def parse_markdown(text):
    """
    Parse le contenu markdown en une liste d'éléments structurés:
    {'type': 'h1'|'h2'|'p'|'code'|'table'|'hr'|'blockquote'|'bullets', ...}
    """
    lines = text.split("\n")
    elements = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # H1
        if line.startswith("# ") and not line.startswith("## "):
            elements.append({"type": "h1", "text": line[2:].strip()})
            i += 1
            continue

        # H2
        if line.startswith("## "):
            elements.append({"type": "h2", "text": line[3:].strip()})
            i += 1
            continue

        # H3
        if line.startswith("### "):
            elements.append({"type": "h3", "text": line[4:].strip()})
            i += 1
            continue

        # HR
        if line.strip() == "---":
            elements.append({"type": "hr"})
            i += 1
            continue

        # Code block (fenced)
        if line.strip().startswith("```"):
            language = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1  # skip closing ```
            code_text = "\n".join(code_lines).strip()
            if code_text:
                elements.append({"type": "code", "text": code_text, "lang": language})
            continue

        # Table (ligne avec | et suivie d'un séparateur ---)
        if "|" in line and i + 1 < len(lines) and re.match(r'^\|?[\s\-:|]+\|', lines[i + 1].strip()):
            # Collecte l'en-tête
            headers = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2  # skip header + separator
            rows = []
            while i < len(lines) and "|" in lines[i]:
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(cells)
                i += 1
            elements.append({"type": "table", "headers": headers, "rows": rows})
            continue

        # Blockquote
        if line.strip().startswith("> "):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith("> "):
                quote_lines.append(lines[i].strip()[2:])
                i += 1
            elements.append({"type": "blockquote", "text": " ".join(quote_lines).strip()})
            continue

        # Bullet list (consecutive lines starting with -)
        if line.strip().startswith("- "):
            bullet_lines = []
            while i < len(lines) and lines[i].strip().startswith("- "):
                bullet_lines.append(lines[i].strip()[2:])
                i += 1
            elements.append({"type": "bullets", "items": bullet_lines})
            continue

        # Numbered list (consecutive lines starting with N.)
        if re.match(r'^\d+\.\s', line.strip()):
            num_lines = []
            while i < len(lines) and re.match(r'^\d+\.\s', lines[i].strip()):
                num_lines.append(re.sub(r'^\d+\.\s+', '', lines[i].strip()))
                i += 1
            elements.append({"type": "numbered", "items": num_lines})
            continue

        # Paragraphe
        para_lines = []
        while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith("#") and "|" not in lines[i] and not lines[i].strip().startswith("```") and not lines[i].strip().startswith("- ") and not re.match(r'^\d+\.\s', lines[i].strip()) and not lines[i].strip().startswith("> ") and lines[i].strip() != "---":
            para_lines.append(lines[i].strip())
            i += 1
        if para_lines:
            raw = " ".join(para_lines).strip()
            if raw:
                elements.append({"type": "p", "text": raw})
        else:
            i += 1

    return elements


def sanitize_unicode(text):
    """Remplace les caractères Unicode absents des polices DejaVu."""
    replacements = {
        "\u2705": "[OK]",       # ✅
        "\u2714": "[OK]",       # ✔
        "\u2713": "[OK]",       # ✓
        "\u274c": "[KO]",       # ❌
        "\u26a0": "[!]",        # ⚠
        "\u2795": "+",          # ➕
        "\u2796": "-",          # ➖
        "\u2013": "-",          # –
        "\u2014": "--",         # —
        "\u2018": "'",          # '
        "\u2019": "'",          # '
        "\u201c": '"',          # "
        "\u201d": '"',          # "
        "\u2026": "...",        # …
        "\u00a0": " ",          # non-breaking space
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text


def md_to_html(text):
    """Convertit le markdown inline en HTML compatible reportlab."""
    text = sanitize_unicode(text)
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
    # Code inline
    text = re.sub(r'`([^`]+)`', r'<font face="DejaVuMono" size="8" color="#13293D">\1</font>', text)
    return text


# ── Construction du document ─────────────────────────────────────────

doc = SimpleDocTemplate(
    OUT,
    pagesize=A4,
    rightMargin=1.4 * cm,
    leftMargin=1.4 * cm,
    topMargin=1.35 * cm,
    bottomMargin=1.7 * cm,
    title="FortiFlow — Guide complet : Revue, Déploiement & HTTPS",
)
story = []

# Lire le markdown
with open(MD_PATH, "r", encoding="utf-8") as f:
    md_text = f.read()

# Extraire le bloc d'en-tête (titre + ligne après le titre + citation de version)
lines = md_text.split("\n")
title_line = lines[0].strip("# ").strip()
subtitle_found = ""
for ln in lines[1:10]:
    stripped = ln.strip()
    if stripped.startswith("> "):
        subtitle_found = md_to_html(stripped[2:].strip())
        break

# ── Page de garde ───────────────────────────────────────────────────
story += [Spacer(1, 1.8 * cm)]
story.append(p("FortiFlow", "CoverTitle"))
story.append(p(subtitle_found if subtitle_found else "Guide complet : Revue, Déploiement & HTTPS", "Subtitle"))
story.append(Spacer(1, 0.3 * cm))
story.append(callout(
    "À propos",
    "FortiFlow est un outil d'analyse de logs trafic <b>FortiGate / FortiAnalyzer</b> pour les prestations de segmentation réseau. "
    "Ce guide couvre l'ensemble du cycle de vie : analyse de code, déploiement Docker (VPS et Portainer), configuration HTTPS et maintenance.",
    LIGHT_GREEN,
))
story.append(PageBreak())

# ── Parsing et rendu ─────────────────────────────────────────────────
elements = parse_markdown(md_text)

# Garder une trace pour ne pas répéter le titre/sous-titre déjà en couverture
skip_first_h1 = True

for elem in elements:
    t = elem["type"]

    if t == "h1":
        if skip_first_h1:
            skip_first_h1 = False
            continue
        story.append(p(md_to_html(elem["text"]), "H1x"))

    elif t == "h2":
        story.append(p(md_to_html(elem["text"]), "H2x"))

    elif t == "h3":
        story.append(p(f"<b>{md_to_html(elem['text'])}</b>", "Bodyx"))

    elif t == "p":
        story.append(p(md_to_html(elem["text"]), "Bodyx"))

    elif t == "code":
        story.append(code_block(elem["text"]))
        story.append(Spacer(1, 0.2 * cm))

    elif t == "table":
        story.append(Spacer(1, 0.15 * cm))
        story.append(make_table(elem["headers"], elem["rows"]))
        story.append(Spacer(1, 0.3 * cm))

    elif t == "hr":
        story.append(Spacer(1, 0.3 * cm))

    elif t == "blockquote":
        # Traiter comme un callout
        body = md_to_html(elem["text"])
        # Détecter si c'est une note spéciale
        if "sécurité" in body.lower() or "fail" in body.lower():
            bg = ORANGE
        elif "version" in body.lower() or "août" in body.lower():
            bg = LIGHT_BLUE
        else:
            bg = LIGHT_BLUE
        story.append(callout("Note", body, bg))
        story.append(Spacer(1, 0.1 * cm))

    elif t == "bullets":
        first = True
        for item in elem["items"]:
            if not first:
                story.append(Spacer(1, 0.05 * cm))
            story.append(bullet(md_to_html(item)))
            first = False
        story.append(Spacer(1, 0.15 * cm))

    elif t == "numbered":
        for idx, item in enumerate(elem["items"], 1):
            story.append(numbered_bullet(idx, md_to_html(item)))
        story.append(Spacer(1, 0.15 * cm))


# ── Génération du PDF ────────────────────────────────────────────────
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"✅ PDF généré : {OUT}")
print(f"   Taille : {__import__('os').path.getsize(OUT):,} octets")
