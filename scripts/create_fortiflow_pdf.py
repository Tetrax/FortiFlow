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
ORANGE_BG = colors.HexColor("#FFF3E0")
GRAY = colors.HexColor("#52606D")
BORDER = colors.HexColor("#D9E2EC")
DARK_TEXT = colors.HexColor("#263238")
CODE_BG = colors.HexColor("#F4F7FA")
CODE_TEXT = colors.HexColor("#13293D")
AMBER = colors.HexColor("#E6960C")
TEAL = colors.HexColor("#00897B")
AMBER_BG = colors.HexColor("#FFF8E7")
TEAL_BG = colors.HexColor("#E6F7F5")
PURPLE = colors.HexColor("#7C4DFF")
PURPLE_BG = colors.HexColor("#F3EEFF")
GHCR_BLUE = colors.HexColor("#2496ED")

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
styles.add(ParagraphStyle(
    name="H4x", parent=styles["Heading3"],
    fontName="DejaVu-Bold", fontSize=10, leading=14,
    textColor=NAVY, spaceBefore=8, spaceAfter=4,
))
styles.add(ParagraphStyle(
    name="OptionLabel", parent=styles["BodyText"],
    fontName="DejaVu-Bold", fontSize=10, leading=14,
    textColor=colors.white,
))
styles.add(ParagraphStyle(
    name="GHCRBadge", parent=styles["BodyText"],
    fontName="DejaVuMono", fontSize=8, leading=11,
    textColor=colors.white,
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


def option_box(option_id, label, body, accent_color):
    """Callout stylisé pour les options de mise à jour (Option A / Option B).

    Affiche un badge coloré avec l'identifiant de l'option (ex: 'Option A'),
    un titre descriptif, et le corps du texte.
    """
    data = [
        [p(f"<b>{option_id}</b>  {label}", "OptionLabel")],
        [p(f"{body}", "Bodyx")],
    ]
    table = Table(data, colWidths=[17.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent_color),
        ("BACKGROUND", (0, 1), (-1, -1), AMBER_BG if "A" in option_id else TEAL_BG),
        ("BOX", (0, 0), (-1, -1), 0.8, accent_color),
        ("LINEBELOW", (0, 0), (-1, 0), 0.4, accent_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def repo_callout(title, body, icon="", accent=PURPLE):
    """Callout pour les sections Portainer Repository / GHCR."""
    header = f"<b>{icon}  {title}</b>" if icon else f"<b>{title}</b>"
    data = [
        [p(header, "H4x")],
        [p(body, "Bodyx")],
    ]
    table = Table(data, colWidths=[17.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PURPLE_BG),
        ("BOX", (0, 0), (-1, -1), 0.8, accent),
        ("LINEBELOW", (0, 0), (-1, 0), 0.4, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
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

        # H4
        if line.startswith("#### "):
            elements.append({"type": "h4", "text": line[5:].strip()})
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
        while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith("#") and not lines[i].strip().startswith("```") and not lines[i].strip().startswith("- ") and not re.match(r'^\d+\.\s', lines[i].strip()) and not lines[i].strip().startswith("> ") and lines[i].strip() != "---":
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

i = 0
while i < len(elements):
    elem = elements[i]
    t = elem["type"]

    if t == "h1":
        if skip_first_h1:
            skip_first_h1 = False
            i += 1
            continue
        story.append(p(md_to_html(elem["text"]), "H1x"))
        i += 1

    elif t == "h2":
        text = md_to_html(elem["text"])
        # Détection Portainer → callout Repository
        if "portainer" in text.lower():
            story.append(Spacer(1, 0.2 * cm))
            story.append(repo_callout(
                title="Repository",
                body=f"<b>{text}</b> — déploiement via registre d'images Docker",
                icon="",
                accent=PURPLE,
            ))
            story.append(Spacer(1, 0.1 * cm))
        # Détection Mise à jour → callout upgrade_path
        elif "mise à jour" in text.lower() or "mise a jour" in text.lower():
            story.append(Spacer(1, 0.2 * cm))
            story.append(repo_callout(
                title="Upgrade Path",
                body=f"<b>{text}</b> — procédure de montée de version",
                icon="",
                accent=TEAL,
            ))
            story.append(Spacer(1, 0.1 * cm))
        else:
            story.append(p(text, "H2x"))
        i += 1

    elif t == "h3":
        story.append(p(f"<b>{md_to_html(elem['text'])}</b>", "Bodyx"))
        i += 1

    elif t == "h4":
        text = elem["text"]
        html_text = md_to_html(text)
        # Détection Option A / Option B → callout avec badge coloré
        is_option_a = text.strip().lower().startswith("option a")
        is_option_b = text.strip().lower().startswith("option b")
        if is_option_a or is_option_b:
            accent = AMBER if is_option_a else TEAL
            # Extraire le label sans le préfixe "Option X —"
            import re as _re
            label = _re.sub(r'^Option\s+[AB]\s*[—\-–]\s*', '', text.strip(), flags=_re.IGNORECASE)
            # Collecter le paragraphe suivant comme corps
            body_text = ""
            if i + 1 < len(elements) and elements[i + 1]["type"] == "p":
                body_text = elements[i + 1]["text"]
                i += 1  # consomme le paragraphe
            story.append(Spacer(1, 0.2 * cm))
            story.append(option_box(
                option_id="Option A" if is_option_a else "Option B",
                label=label,
                body=md_to_html(body_text) if body_text else "",
                accent_color=accent,
            ))
            story.append(Spacer(1, 0.1 * cm))
        else:
            story.append(p(f"<b>{html_text}</b>", "H4x"))
        i += 1

    elif t == "p":
        raw_html = md_to_html(elem["text"])
        # Détection GHCR → ajout d'un badge visuel
        if "ghcr.io" in elem["text"].lower() or "github container registry" in elem["text"].lower():
            story.append(Spacer(1, 0.1 * cm))
            ghcr_badge = Table(
                [[p(raw_html, "Bodyx")]],
                colWidths=[17.2 * cm],
            )
            ghcr_badge.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E8F4FD")),
                ("BOX", (0, 0), (-1, -1), 0.6, GHCR_BLUE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(ghcr_badge)
            story.append(Spacer(1, 0.1 * cm))
        else:
            story.append(p(raw_html, "Bodyx"))
        i += 1

    elif t == "code":
        code_text = elem["text"]
        story.append(code_block(code_text))
        story.append(Spacer(1, 0.2 * cm))
        # Si le bloc contient ghcr.io, ajouter un petit badge d'info
        if "ghcr.io" in code_text.lower():
            story.append(p(
                '<font face="DejaVuMono" size="7" color="#2496ED">'
                '  GHCR — GitHub Container Registry</font>',
                "Small"
            ))
            story.append(Spacer(1, 0.1 * cm))
        i += 1

    elif t == "table":
        story.append(Spacer(1, 0.15 * cm))
        story.append(make_table(elem["headers"], elem["rows"]))
        story.append(Spacer(1, 0.3 * cm))
        i += 1

    elif t == "hr":
        story.append(Spacer(1, 0.3 * cm))
        i += 1

    elif t == "blockquote":
        # Traiter comme un callout
        body = md_to_html(elem["text"])
        # Détecter si c'est une note spéciale
        if "sécurité" in body.lower() or "fail" in body.lower():
            bg = ORANGE_BG
        elif "ghcr.io" in elem["text"].lower() or "github container registry" in elem["text"].lower():
            bg = colors.HexColor("#E8F4FD")  # GHCR blue
        elif "version" in body.lower() or "août" in body.lower():
            bg = LIGHT_BLUE
        else:
            bg = LIGHT_BLUE
        story.append(callout("Note", body, bg))
        story.append(Spacer(1, 0.1 * cm))
        i += 1

    elif t == "bullets":
        first = True
        for item in elem["items"]:
            if not first:
                story.append(Spacer(1, 0.05 * cm))
            story.append(bullet(md_to_html(item)))
            first = False
        story.append(Spacer(1, 0.15 * cm))
        i += 1

    elif t == "numbered":
        for idx, item in enumerate(elem["items"], 1):
            story.append(numbered_bullet(idx, md_to_html(item)))
        story.append(Spacer(1, 0.15 * cm))
        i += 1

    else:
        i += 1


# ── Génération du PDF ────────────────────────────────────────────────
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"✅ PDF généré : {OUT}")
print(f"   Taille : {__import__('os').path.getsize(OUT):,} octets")
