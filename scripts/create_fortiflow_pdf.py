#!/usr/bin/env python3
"""Génère le PDF du guide FortiFlow — style Upgrade Path (procédure d'exploitation)."""

from __future__ import annotations

from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, XPreformatted,
)

OUTPUT = Path("/opt/data/FortiFlow/docs/fortiflow-tutoriel.pdf")
PW, PH = A4
MX, MT, MB = 1.4 * cm, 1.35 * cm, 1.7 * cm
CW = PW - 2 * MX
NAVY = colors.HexColor("#0F2747")
BLUE = colors.HexColor("#1976D2")
INK = colors.HexColor("#243B53")
MUTED = colors.HexColor("#627D98")
LINE = colors.HexColor("#BCCCDC")
PALE_BLUE = colors.HexColor("#EAF3FB")
PALE_CYAN = colors.HexColor("#E8F7F8")
PALE_YELLOW = colors.HexColor("#FFF8DB")
PALE_RED = colors.HexColor("#FDECEC")
PALE_GREEN = colors.HexColor("#EAF8F1")
CODE_BG = colors.HexColor("#F4F7FA")
AMBER = colors.HexColor("#E6960C")
TEAL = colors.HexColor("#00897B")
AMBER_BG = colors.HexColor("#FFF8E7")
TEAL_BG = colors.HexColor("#E6F7F5")
GHCR_BLUE = colors.HexColor("#2496ED")

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
pdfmetrics.registerFont(TTFont("DV", f"{FONT_DIR}/DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("DV-B", f"{FONT_DIR}/DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("DVM", f"{FONT_DIR}/DejaVuSansMono.ttf"))

S = {
    "title": ParagraphStyle("title", fontName="DV-B", fontSize=24, leading=30,
                            textColor=NAVY, spaceAfter=7 * mm),
    "subtitle": ParagraphStyle("subtitle", fontName="DV", fontSize=11.5, leading=17,
                               textColor=MUTED, spaceAfter=6 * mm),
    "h1": ParagraphStyle("h1", fontName="DV-B", fontSize=16.5, leading=21,
                         textColor=NAVY, spaceAfter=4 * mm),
    "h2": ParagraphStyle("h2", fontName="DV-B", fontSize=12, leading=15,
                         textColor=BLUE, spaceBefore=3 * mm, spaceAfter=2 * mm),
    "body": ParagraphStyle("body", fontName="DV", fontSize=9, leading=13,
                           textColor=INK, spaceAfter=2.4 * mm),
    "small": ParagraphStyle("small", fontName="DV", fontSize=7.7, leading=10.2,
                            textColor=MUTED, spaceAfter=1.5 * mm),
    "bullet": ParagraphStyle("bullet", fontName="DV", fontSize=9, leading=12.5,
                             textColor=INK, leftIndent=5 * mm, firstLineIndent=-3.5 * mm,
                             bulletIndent=0, spaceAfter=1.3 * mm),
    "code": ParagraphStyle("code", fontName="DVM", fontSize=6.8, leading=9.1,
                           textColor=colors.HexColor("#1F2933")),
    "boxTitle": ParagraphStyle("boxTitle", fontName="DV-B", fontSize=9.2,
                               leading=12, textColor=NAVY, spaceAfter=1.3 * mm),
    "tableHead": ParagraphStyle("tableHead", fontName="DV-B", fontSize=8.5,
                                leading=11, textColor=colors.white),
    "tableBody": ParagraphStyle("tableBody", fontName="DV", fontSize=8.5,
                                leading=11, textColor=INK),
    "checklist": ParagraphStyle("checklist", fontName="DV", fontSize=9, leading=12.5,
                                textColor=INK, leftIndent=5 * mm, firstLineIndent=-3.5 * mm,
                                bulletIndent=0, spaceAfter=1.5 * mm),
}


def sanitize_unicode(text: str) -> str:
    """Remplace les caractères Unicode absents des polices DejaVu."""
    replacements = {
        "\u2705": "[OK]", "\u2714": "[OK]", "\u2713": "[OK]",
        "\u274c": "[KO]", "\u26a0": "[!]",
        "\u2795": "+", "\u2796": "-",
        "\u2013": "-", "\u2014": "--",
        "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u00a0": " ",
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(MX, 11 * mm, PW - MX, 11 * mm)
    canvas.setFont("DV", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MX, 6.5 * mm, "FortiFlow — Guide de déploiement")
    canvas.drawRightString(PW - MX, 6.5 * mm, f"Page {doc.page}")
    canvas.restoreState()


def para(text, style="body"):
    return Paragraph(sanitize_unicode(text), S[style])


def h(text, level=1):
    return para(text, "h1" if level == 1 else "h2")


def bullet(text):
    return Paragraph(sanitize_unicode(text), S["bullet"], bulletText="•")


def checklist_item(text):
    return Paragraph(sanitize_unicode(text), S["checklist"], bulletText="☐")


def code(text):
    content = XPreformatted(escape(text.strip()), S["code"])
    table = Table([[content]], colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return KeepTogether([table, Spacer(1, 3 * mm)])


def callout(title, body, color=PALE_BLUE):
    border_color = BLUE
    if color == PALE_RED:
        border_color = colors.HexColor("#C62828")
    elif color == PALE_YELLOW:
        border_color = AMBER
    table = Table([[[para(title, "boxTitle"), para(body)]]], colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("BOX", (0, 0), (-1, -1), 0.7, border_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return KeepTogether([table, Spacer(1, 4 * mm)])


def step(number, title, body):
    """Étape numérotée avec badge bleu, comme dans le guide Upgrade Path."""
    badge_style = ParagraphStyle(f"badge{number}", fontName="DV-B",
                                 fontSize=11, leading=14, textColor=colors.white,
                                 alignment=1)
    table = Table([[Paragraph(f"<b>{number}</b>", badge_style),
                    [para(f"<b>{title}</b>", "boxTitle"), para(body)]]],
                  colWidths=[12 * mm, CW - 12 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), BLUE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 4),
        ("RIGHTPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 0), (0, 0), 5),
        ("BOTTOMPADDING", (0, 0), (0, 0), 5),
        ("LEFTPADDING", (1, 0), (1, 0), 7),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("TOPPADDING", (1, 0), (1, 0), 1),
    ]))
    return KeepTogether([table, Spacer(1, 3 * mm)])


def make_data_table(headers, rows):
    """Tableau de données avec en-tête marine."""
    head_row = [para(h, "tableHead") for h in headers]
    data_rows = [[para(cell, "tableBody") for cell in row] for row in rows]
    data = [head_row] + data_rows
    ncols = len(headers)
    tbl = Table(data, colWidths=[CW / ncols] * ncols, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "DV-B"),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFBFC")))
    tbl.setStyle(TableStyle(style))
    return KeepTogether([tbl, Spacer(1, 4 * mm)])


def ghcr_badge():
    """Badge GHCR pour la page de garde."""
    badge = Table([[para('<font color="white"><b>ghcr.io/tetrax/fortiflow:latest</b></font>', "code")]],
                  colWidths=[10 * cm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GHCR_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.8, GHCR_BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return badge


# ── Construction du document ─────────────────────────────────────────

doc = BaseDocTemplate(
    str(OUTPUT), pagesize=A4, leftMargin=MX, rightMargin=MX,
    topMargin=MT, bottomMargin=MB,
    title="Guide de Déploiement FortiFlow",
    author="Hermes Agent",
    subject="Déploiement Docker, Portainer et certificats pour FortiFlow",
)
frame = Frame(MX, MB, CW, PH - MT - MB, id="main")
doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

story = [
    # ── Page de garde ──
    Spacer(1, 15 * mm),
    para("GUIDE DE DÉPLOIEMENT", "small"),
    para("FortiFlow", "title"),
    para("Analyse de logs trafic FortiGate / FortiAnalyzer — segmentation réseau. "
         "Import, matrice de flux, rapprochement configuration/routage, génération CLI FortiGate.", "subtitle"),
    callout("Architecture",
            "Un seul conteneur Docker <b>fortiflow</b> (Node.js + Express, port interne 3737). "
            "Image hébergée sur GitHub Container Registry, déployée via Portainer en mode Repository. "
            "13 variables d'environnement, support TLS natif, healthcheck intégré.",
            PALE_CYAN),
    callout("FQDN utilisé dans les exemples",
            "Cette procédure utilise <b>fortiflow.monentreprise.lan</b>. Le remplacer partout si le FQDN définitif est différent. "
            "Le certificat doit contenir ce nom dans un SAN DNS explicite.",
            PALE_YELLOW),
    h("Sommaire", 2),
    para("1. Présentation du projet<br/>"
         "2. ÉTAPE 1 — Connexion à la VM de production<br/>"
         "3. ÉTAPE 2 — Création des répertoires persistants<br/>"
         "4. ÉTAPE 3 — Vérification du port 13737<br/>"
         "5. ÉTAPE 4 — Déploiement du stack dans Portainer<br/>"
         "6. ÉTAPE 5 — Vérification du bon fonctionnement<br/>"
         "7. ÉTAPE 6 — Mise en place du HTTPS<br/>"
         "8. Mise à jour future<br/>"
         "9. Dépannage<br/>"
         "10. Checklist finale"),
    Spacer(1, 6 * mm),

    # Tableau machines
    make_data_table(
        ["Machine", "Où ?", "Qui ?", "Accès"],
        [
            ["SOURCE (dev)", "VPS IONOS", "Da Vinci (Hermes)", "Automatique (CI/CD)"],
            ["DESTINATION (prod)", "VM Entreprise", "Valentin", "Console/SSH (root)"],
        ]
    ),

    para("Version du document : 3 août 2026", "small"),
    para("CI : VERTE (4/4)  |  Image : ghcr.io/tetrax/fortiflow:latest", "small"),
    PageBreak(),

    # ── 1. Présentation ──
    h("1. Présentation du projet"),
    para("FortiFlow est un outil d'analyse de logs trafic <b>FortiGate / FortiAnalyzer</b> pour les prestations de segmentation réseau. "
         "Il importe les logs trafic, conserve leur contexte FortiGate/VDOM, construit les matrices de flux, rapproche les observations "
         "de la configuration et du routage, puis prépare une CLI FortiGate destinée à être revue par un ingénieur."),
    bullet("Un seul conteneur Docker : <b>fortiflow</b> (Node.js + Express, port interne 3737)."),
    bullet("Image hébergée sur <b>ghcr.io/tetrax/fortiflow:latest</b> — déjà buildée par la CI, rien à builder."),
    bullet("13 variables d'environnement configurables (PORT, DOMAIN, MAX_UPLOAD_SIZE_MB, etc.)."),
    bullet("Support TLS natif (sans Nginx) ou via reverse proxy Nginx."),
    bullet("Healthcheck intégré, rate limiting, graceful shutdown."),
    bullet("CI : build Docker + scan Trivy + push GHCR (4 jobs, tous verts)."),
    callout("Déploiement interne uniquement",
            "L'application ne sera PAS exposée sur Internet. Certificat TLS : PKI entreprise. "
            "Nom de domaine : <b>fortiflow.monentreprise.lan</b>.",
            PALE_GREEN),
    PageBreak(),

    # ── ÉTAPE 1 ──
    h("2. ÉTAPE 1 — Connexion à la VM de production"),
    callout("Ce que tu vas faire",
            "Te connecter en <b>root</b> sur la VM de l'entreprise où tourne Portainer, "
            "et vérifier que Docker et Portainer sont opérationnels.",
            PALE_CYAN),
    h("Commande", 2),
    code("""# Depuis ton poste :
ssh root@ADRESSE_IP_DE_LA_VM

# Vérifier Portainer :
docker ps | grep portainer
# → Doit afficher une ligne

# Vérifier Docker :
docker version
# → Doit être ≥ 24.0"""),
    PageBreak(),

    # ── ÉTAPE 2 ──
    h("3. ÉTAPE 2 — Création des répertoires persistants"),
    callout("Ce que tu vas faire",
            "Créer les répertoires sur l'hôte qui seront montés dans le conteneur. "
            "Les conteneurs sont éphémères, les données doivent survivre aux mises à jour. "
            "Deux répertoires : <b>/srv/fortiflow/data</b> et <b>/srv/fortiflow/certificates</b>.",
            PALE_CYAN),
    h("Commande", 2),
    code("""mkdir -p /srv/fortiflow/data /srv/fortiflow/certificates
chown -R 1000:1000 /srv/fortiflow
ls -la /srv/fortiflow/
# Doit afficher data/ certificates/ avec 1000:1000"""),
    callout("UID Docker",
            "Si Docker utilise un UID différent : <b>id docker</b> pour trouver le bon et adapter le chown.",
            PALE_YELLOW),
    PageBreak(),

    # ── ÉTAPE 3 ──
    h("4. ÉTAPE 3 — Vérification du port 13737"),
    callout("Ce que tu vas faire",
            "Vérifier que le port <b>13737</b> (ou 443 si HTTPS direct) est libre sur l'hôte. "
            "L'application utilise le port 13737 en externe, mappé vers 3737 dans le conteneur.",
            PALE_CYAN),
    h("Commande", 2),
    code("""ss -tlnp | grep 13737
# RIEN affiché → OK. Sinon → choisir un autre port."""),
    PageBreak(),

    # ── ÉTAPE 4 ──
    h("5. ÉTAPE 4 — Déploiement du stack dans Portainer"),
    callout("Ce que tu vas faire",
            "Créer un <b>stack</b> Portainer en mode Repository. Portainer télécharge automatiquement "
            "l'image depuis <b>ghcr.io/tetrax/fortiflow:latest</b> et démarre le conteneur.",
            PALE_CYAN),

    h("Ouvrir Portainer", 2),
    code("""https://ADRESSE_IP_DE_LA_VM:9443
# Se connecter"""),

    h("Créer le stack", 2),
    step("1", "Accéder aux stacks",
         "Menu gauche → <b>Stacks</b> → <b>+ Add stack</b>."),
    step("2", "Nommer le stack",
         "Name : <b>fortiflow</b>"),
    step("3", "Configurer le Repository",
         "Build method : <b>Repository</b>"),
    step("4", "URL et référence",
         "Repository URL : <b>https://github.com/Tetrax/FortiFlow</b><br/>"
         "Repository reference : <b>refs/heads/main</b><br/>"
         "Compose path : <b>docker-compose.portainer.yml</b>"),
    step("5", "Renseigner les variables d'environnement",
         "Section <b>Environment variables</b> → <b>+ Add environment variable</b> pour chaque ligne du tableau ci-dessous."),

    make_data_table(
        ["Nom", "Valeur"],
        [
            ["PORT", "3737"],
            ["DOMAIN", "devval.com"],
            ["MAX_UPLOAD_SIZE_MB", "2048"],
            ["MAX_DECOMPRESSED_SIZE_MB", "4096"],
            ["MAX_ARCHIVE_ENTRIES", "100"],
            ["MAX_XLSX_SIZE_MB", "100"],
            ["MAX_WORKSPACE_UNCOMPRESSED_MB", "1024"],
            ["MAX_SESSION_DEDUPE_KEYS", "2000000"],
            ["MAX_ANALYSIS_WORKERS", "1"],
            ["MAX_ANALYSIS_QUEUE", "3"],
            ["ANALYSIS_WORKER_MEMORY_MB", "0"],
            ["SSL_KEY", "/certs/privkey.pem"],
            ["SSL_CERT", "/certs/fullchain.pem"],
        ]
    ),

    callout("Ne pas dupliquer SSL_KEY / SSL_CERT",
            "Ces variables sont déjà dans le compose. Les renseigner dans Portainer uniquement si "
            "tu les surcharges avec des valeurs différentes.",
            PALE_YELLOW),

    step("6", "Déployer",
         "Cliquer <b>Deploy the stack</b>. Portainer : 1) Pull ghcr.io 2) Crée le conteneur 3) Démarre (~15s)."),

    callout("Fichier compose",
            "Le fichier <b>docker-compose.portainer.yml</b> référence l'image <b>ghcr.io/tetrax/fortiflow:latest</b>. "
            "Portainer la télécharge automatiquement. Aucun build local nécessaire.",
            PALE_BLUE),
    PageBreak(),

    # ── ÉTAPE 5 ──
    h("6. ÉTAPE 5 — Vérification du bon fonctionnement"),
    callout("Ce que tu vas faire",
            "Vérifier que le conteneur est bien démarré, que l'application répond en HTTP, "
            "et que le dashboard est accessible depuis le réseau interne.",
            PALE_CYAN),

    h("Depuis Portainer", 2),
    step("1", "Contrôler le conteneur",
         "Dans <b>Containers</b>, le conteneur <b>fortiflow</b> doit afficher <b>running (healthy)</b>."),

    h("Depuis le terminal SSH root", 2),
    step("2", "Vérifier avec Docker",
         "Trois contrôles rapides pour valider le déploiement."),
    code("""docker ps --filter "name=fortiflow"
# → Doit afficher le conteneur avec statut healthy

curl -s http://localhost:13737/ | head -10
# → Doit afficher du HTML avec "FortiFlow"

docker logs fortiflow --tail 30
# → Vérifier l'absence d'erreurs critiques"""),

    h("Depuis un navigateur", 2),
    step("3", "Test navigateur",
         "Depuis un poste du réseau interne, ouvrir <b>http://ADRESSE_IP_DE_LA_VM:13737</b>. "
         "Le dashboard FortiFlow doit s'afficher."),
    PageBreak(),

    # ── ÉTAPE 6 ──
    h("7. ÉTAPE 6 — Mise en place du HTTPS"),
    callout("Ce que tu vas faire",
            "Configurer le certificat TLS interne pour que l'application soit accessible en HTTPS sur "
            "<b>https://fortiflow.monentreprise.lan</b>. Deux options : avec Nginx (recommandé en entreprise) "
            "ou TLS direct dans l'application (sans Nginx).",
            PALE_CYAN),

    callout("PKI interne obligatoire pour .lan",
            "Let's Encrypt ne signe normalement pas un suffixe privé <b>.lan</b>. "
            "La CA interne doit être distribuée aux postes, typiquement par GPO ou MDM.",
            PALE_YELLOW),

    # -- Option A --
    Spacer(1, 4 * mm),
    para('<font color="#E6960C"><b>OPTION A — Avec Nginx (recommandé en entreprise)</b></font>', "h2"),

    h("Obtenir le certificat", 2),
    para("Demander à l'équipe IT les deux fichiers pour <b>fortiflow.monentreprise.lan</b> (ou wildcard <b>*.monentreprise.lan</b>) :"),
    bullet("Certificat public : <b>fortiflow.lan.crt</b>"),
    bullet("Clé privée : <b>fortiflow.lan.key</b>"),

    h("Transférer vers la VM", 2),
    code("""scp fortiflow.lan.crt root@VM_IP:/srv/fortiflow/certificates/
scp fortiflow.lan.key root@VM_IP:/srv/fortiflow/certificates/"""),

    h("Placer les certificats", 2),
    code("""cd /srv/fortiflow/certificates
ls -la  # Doit afficher fortiflow.lan.crt et fortiflow.lan.key
chmod 600 fortiflow.lan.key
chmod 644 fortiflow.lan.crt
chown -R 1000:1000 /srv/fortiflow/certificates"""),

    h("Configurer Nginx", 2),
    para("Créer le fichier de configuration du site :"),
    code("""nano /etc/nginx/sites-available/fortiflow"""),
    para("Coller ce contenu :"),
    code("""server {
    listen 443 ssl http2;
    server_name fortiflow.monentreprise.lan;

    ssl_certificate     /srv/fortiflow/certificates/fortiflow.lan.crt;
    ssl_certificate_key /srv/fortiflow/certificates/fortiflow.lan.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 2048m;
    proxy_read_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:13737;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}"""),

    h("Activer le site", 2),
    code("""ln -s /etc/nginx/sites-available/fortiflow /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx"""),

    h("DNS interne", 2),
    para("Demander à l'équipe IT un enregistrement DNS interne :"),
    code("""fortiflow.monentreprise.lan → IP_VM"""),
    callout("En attendant le DNS",
            "Ajouter <b>IP_VM  fortiflow.monentreprise.lan</b> dans <b>/etc/hosts</b> de ton poste pour tester.",
            PALE_YELLOW),

    PageBreak(),

    # -- Option B --
    para('<font color="#00897B"><b>OPTION B — TLS direct sans Nginx (alternative)</b></font>', "h2"),

    callout("Principe",
            "L'application gère elle-même le TLS. Les certificats sont placés dans <b>/etc/ssl/fortiflow/</b> "
            "sur l'hôte, montés en <b>/certs/</b> dans le conteneur (lecture seule). "
            "Le serveur détecte automatiquement leur présence et bascule en HTTPS.",
            PALE_CYAN),

    h("Placer les certificats", 2),
    code("""mkdir -p /etc/ssl/fortiflow/

# Copier la clé privée et le certificat
cp /chemin/vers/privkey.pem /etc/ssl/fortiflow/privkey.pem
cp /chemin/vers/fullchain.pem /etc/ssl/fortiflow/fullchain.pem

chmod 600 /etc/ssl/fortiflow/privkey.pem
chmod 644 /etc/ssl/fortiflow/fullchain.pem
chown -R 1000:1000 /etc/ssl/fortiflow/
ls -la /etc/ssl/fortiflow/
# Doit afficher privkey.pem et fullchain.pem avec 1000:1000"""),

    h("Variables d'environnement", 2),
    para("Vérifier que les variables TLS sont bien présentes dans le stack :"),
    code("""SSL_KEY=/certs/privkey.pem
SSL_CERT=/certs/fullchain.pem"""),

    h("Redéployer", 2),
    step("1", "Mettre à jour le stack",
         "Dans Portainer : <b>Stacks → fortiflow → Pull and redeploy → Update</b>."),

    callout("Important",
            "Avec TLS direct, l'application écoute en HTTPS sur le port 13737 (plus HTTP). "
            "Le test curl doit devenir : <b>curl -k https://localhost:13737</b>",
            PALE_RED),
    PageBreak(),

    # ── Mise à jour future ──
    h("8. Mise à jour future"),
    callout("Ce que tu vas faire",
            "Mettre à jour l'application vers la dernière version disponible sur GHCR. "
            "Deux méthodes : Portainer (recommandé) ou SSH (plan B).",
            PALE_CYAN),

    h("Portainer (recommandé)", 2),
    step("1", "Pull and redeploy",
         "Dans Portainer : <b>Stacks → fortiflow → Pull and redeploy → Update</b>. "
         "Portainer pull la dernière image <b>ghcr.io/tetrax/fortiflow:latest</b> et redémarre (~5 sec d'interruption)."),

    h("SSH (plan B)", 2),
    code("""cd /srv/fortiflow
docker compose -f docker-compose.portainer.yml pull
docker compose -f docker-compose.portainer.yml up -d"""),
    para("Le compose référence ghcr.io directement → <b>docker compose pull</b> fonctionne."),
    PageBreak(),

    # ── Dépannage ──
    h("9. Dépannage"),
    make_data_table(
        ["Problème", "Vérification / Action"],
        [
            ["Stack ne se déploie pas", "Vérifier toutes les variables : PORT, DOMAIN, MAX_UPLOAD_SIZE_MB, etc."],
            ["Conteneur en erreur", "chown -R 1000:1000 /srv/fortiflow puis docker logs fortiflow"],
            ["Statut healthy absent", "Vérifier que le healthcheck est présent dans le compose"],
            ["HTTPS ne fonctionne pas", "Vérifier les chemins dans Nginx, nginx -t, vérifier le DNS interne"],
            ["Certificat non reconnu", "Vérifier que le poste fait confiance à la CA racine de l'entreprise"],
            ["Dashboard page blanche", "docker logs fortiflow --tail 50, vérifier les variables d'environnement"],
            ["Erreur ANALYSIS_CANCELLED", "Analyse interrompue — relancer l'upload"],
            ["Erreur DECOMPRESSED_SIZE_LIMIT", "Archive trop volumineuse — augmenter MAX_DECOMPRESSED_SIZE_MB"],
            ["Portainer : no such image", "Utiliser la méthode Repository (pas d'import manuel)"],
            ["Permission denied sur /certs", "chmod 644 sur les .pem dans /etc/ssl/fortiflow/"],
        ]
    ),
    PageBreak(),

    # ── Checklist ──
    h("10. Checklist finale"),
    checklist_item("/srv/fortiflow/ créé avec permissions/ownership 1000:1000"),
    checklist_item("Port 13737 libre (ss -tlnp | grep 13737)"),
    checklist_item("Stack Portainer déployé, conteneur healthy"),
    checklist_item("curl http://localhost:13737 fonctionne"),
    checklist_item("Certificats dans /srv/fortiflow/certificates/ (Nginx) ou /etc/ssl/fortiflow/ (TLS direct)"),
    checklist_item("Nginx configuré pour HTTPS sur fortiflow.monentreprise.lan (Option A)"),
    checklist_item("DNS interne créé (fortiflow.monentreprise.lan → IP_VM)"),
    checklist_item("https://fortiflow.monentreprise.lan accessible, cadenas vert"),
    Spacer(1, 6 * mm),
    callout("Déploiement terminé",
            "Application accessible en HTTPS sur le réseau interne. "
            "Repo : https://github.com/Tetrax/FortiFlow  |  Image : ghcr.io/tetrax/fortiflow:latest  |  "
            "CI : https://github.com/Tetrax/FortiFlow/actions",
            PALE_GREEN),
]

doc.build(story)
print(f"PDF généré : {OUTPUT}")
print(f"Taille : {OUTPUT.stat().st_size:,} octets")
