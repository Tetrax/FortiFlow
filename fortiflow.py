#!/usr/bin/env python3
"""
FortiFlow - Analyseur de logs trafic FortiGate/FortiAnalyzer

Agrège les flux réseau pour identifier les communications inter-segments
et faciliter la création de politiques de pare-feu.

Usage:
    python fortiflow.py traffic.log
    python fortiflow.py traffic.log --output csv > flows.csv
    python fortiflow.py traffic.log --mode policy --subnet 24
    python fortiflow.py *.log --src-only private --action accept
    cat traffic.log | python fortiflow.py -
"""

import sys
import re
import csv
import ipaddress
import argparse
import io
from collections import defaultdict
from pathlib import Path

# ─────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────

RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

PROTO_MAP = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "89": "OSPF",
}

# ─────────────────────────────────────────────
# Utilitaires IP
# ─────────────────────────────────────────────

def is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in RFC1918)
    except ValueError:
        return False


def ip_type(ip_str: str) -> str:
    """Retourne 'private' ou 'public'."""
    return "private" if is_private(ip_str) else "public"


def get_subnet(ip_str: str, prefix: int) -> str:
    """Retourne le réseau CIDR contenant l'IP."""
    try:
        net = ipaddress.ip_interface(f"{ip_str}/{prefix}").network
        return str(net)
    except ValueError:
        return ip_str


# ─────────────────────────────────────────────
# Parser FortiGate
# ─────────────────────────────────────────────

_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s"]\S*)')


def parse_line(line: str) -> dict:
    """Parse une ligne de log FortiGate (format key=value)."""
    fields = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        val = m.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        fields[key] = val
    return fields


def iter_logs(files: list) -> tuple:
    """
    Itère sur toutes les lignes de log en streaming (gère les gros fichiers).
    Yield: (fields_dict, line_number, filename)
    """
    for filename in files:
        if filename == "-":
            src = sys.stdin
            name = "<stdin>"
        else:
            try:
                src = open(filename, "r", encoding="utf-8", errors="replace")
                name = filename
            except OSError as e:
                print(f"[ERREUR] {e}", file=sys.stderr)
                continue

        with src if filename == "-" else src:
            for lineno, line in enumerate(src, 1):
                line = line.strip()
                if not line:
                    continue
                fields = parse_line(line)
                yield fields, lineno, name


# ─────────────────────────────────────────────
# Filtres
# ─────────────────────────────────────────────

def should_include(fields: dict, args) -> bool:
    """Retourne True si cette entrée de log doit être incluse dans l'analyse."""
    # Seulement les logs de trafic
    if fields.get("type") not in ("traffic", ""):
        # Certains logs n'ont pas de champ type (inline) — on garde si srcip présent
        if "type" in fields and fields["type"] != "traffic":
            return False

    srcip = fields.get("srcip", "")
    dstip = fields.get("dstip", "")

    if not srcip or not dstip:
        return False

    # Filtre source
    if args.src_only == "private" and not is_private(srcip):
        return False
    if args.src_only == "public" and is_private(srcip):
        return False

    # Filtre destination
    if args.dst_only == "private" and not is_private(dstip):
        return False
    if args.dst_only == "public" and is_private(dstip):
        return False

    # Filtre action
    if args.action and fields.get("action", "").lower() not in args.action:
        return False

    # Filtre VDOM
    if args.vdom and fields.get("vd", fields.get("vdom", "")) not in args.vdom:
        return False

    return True


# ─────────────────────────────────────────────
# Agrégation
# ─────────────────────────────────────────────

class FlowKey:
    """Clé d'agrégation d'un flux."""
    __slots__ = ("src", "dst", "dstport", "proto", "service")

    def __init__(self, src, dst, dstport, proto, service):
        self.src = src
        self.dst = dst
        self.dstport = dstport
        self.proto = proto
        self.service = service

    def as_tuple(self):
        return (self.src, self.dst, self.dstport, self.proto, self.service)

    def __hash__(self):
        return hash(self.as_tuple())

    def __eq__(self, other):
        return self.as_tuple() == other.as_tuple()


class FlowStats:
    __slots__ = ("sessions", "sent_bytes", "rcvd_bytes", "actions")

    def __init__(self):
        self.sessions = 0
        self.sent_bytes = 0
        self.rcvd_bytes = 0
        self.actions = defaultdict(int)

    def add(self, fields: dict):
        self.sessions += 1
        self.sent_bytes += int(fields.get("sentbyte", 0) or 0)
        self.rcvd_bytes += int(fields.get("rcvdbyte", 0) or 0)
        action = fields.get("action", "unknown")
        self.actions[action] += 1

    @property
    def total_bytes(self):
        return self.sent_bytes + self.rcvd_bytes

    @property
    def dominant_action(self):
        if not self.actions:
            return "unknown"
        return max(self.actions, key=self.actions.get)


def get_service_label(fields: dict) -> str:
    """Retourne le label de service le plus lisible disponible."""
    service = fields.get("service", "")
    if service and service not in ("N/A", ""):
        return service.upper()
    dstport = fields.get("dstport", "")
    proto = fields.get("proto", "")
    proto_name = PROTO_MAP.get(proto, f"proto{proto}" if proto else "")
    if dstport and proto_name:
        return f"{proto_name}/{dstport}"
    if dstport:
        return f"port/{dstport}"
    return proto_name or "UNKNOWN"


def aggregate(files: list, args) -> dict:
    """
    Parcourt les fichiers et retourne un dict FlowKey -> FlowStats.
    Traitement en streaming pour supporter les fichiers de 200MB+.
    """
    flows = defaultdict(FlowStats)
    total_lines = 0
    matched_lines = 0

    for fields, lineno, fname in iter_logs(files):
        total_lines += 1
        if not should_include(fields, args):
            continue
        matched_lines += 1

        srcip = fields["srcip"]
        dstip = fields["dstip"]
        dstport = fields.get("dstport", "")
        proto = fields.get("proto", "")
        service = get_service_label(fields)

        # Mode subnet : on remplace les IPs par leur réseau
        if args.mode in ("policy", "subnet"):
            if is_private(srcip):
                srcip = get_subnet(srcip, args.subnet)
            if is_private(dstip):
                dstip = get_subnet(dstip, args.subnet)

        key = FlowKey(srcip, dstip, dstport, proto, service)
        flows[key].add(fields)

    if args.verbose:
        print(
            f"[INFO] {total_lines} lignes lues, {matched_lines} flux retenus, "
            f"{len(flows)} entrées uniques",
            file=sys.stderr,
        )

    return flows


# ─────────────────────────────────────────────
# Formatage de la sortie
# ─────────────────────────────────────────────

def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_number(n: int) -> str:
    return f"{n:,}".replace(",", " ")


COLS = [
    ("Source",       "src",      40),
    ("Destination",  "dst",      40),
    ("Service",      "service",  18),
    ("Proto",        "proto",     6),
    ("Port dst",     "dstport",   8),
    ("Sessions",     "sessions", 10),
    ("Octets",       "bytes",    12),
    ("Action",       "action",   10),
]


def output_table(flows: dict, args):
    """Affiche un tableau formaté dans le terminal."""
    rows = build_rows(flows)
    rows = sort_rows(rows, args)
    rows = rows[: args.top] if args.top else rows

    # Largeurs dynamiques
    widths = {c[1]: max(c[2], len(c[0])) for c in COLS}
    for r in rows:
        for _, field, _ in COLS:
            widths[field] = max(widths[field], len(str(r.get(field, ""))))

    header = "  ".join(c[0].ljust(widths[c[1]]) for c in COLS)
    sep = "  ".join("-" * widths[c[1]] for c in COLS)

    print(header)
    print(sep)
    for r in rows:
        line = "  ".join(str(r.get(c[1], "")).ljust(widths[c[1]]) for c in COLS)
        print(line)

    print(f"\n{len(rows)} flux agrégés")


def output_csv(flows: dict, args):
    """Sortie CSV (stdout)."""
    rows = build_rows(flows)
    rows = sort_rows(rows, args)
    rows = rows[: args.top] if args.top else rows

    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["src", "dst", "service", "proto", "dstport", "sessions",
                    "sent_bytes", "rcvd_bytes", "bytes", "action"],
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)


def output_policy(flows: dict, args):
    """
    Affiche des suggestions de règles de firewall groupées par paire src→dst.
    Format : SOURCE → DESTINATION | SERVICES
    """
    # On regroupe par (src, dst)
    pairs = defaultdict(lambda: {"services": set(), "sessions": 0, "bytes": 0, "actions": defaultdict(int)})

    for key, stats in flows.items():
        p = pairs[(key.src, key.dst)]
        p["services"].add(key.service)
        p["sessions"] += stats.sessions
        p["bytes"] += stats.total_bytes
        for a, c in stats.actions.items():
            p["actions"][a] += c

    rows = []
    for (src, dst), data in pairs.items():
        services = ", ".join(sorted(data["services"]))
        action = max(data["actions"], key=data["actions"].get) if data["actions"] else "unknown"
        rows.append({
            "src": src,
            "dst": dst,
            "services": services,
            "sessions": data["sessions"],
            "bytes": data["bytes"],
            "action": action,
            "src_type": ip_type(src.split("/")[0]),
            "dst_type": ip_type(dst.split("/")[0]),
        })

    rows.sort(key=lambda r: (-r["sessions"], r["src"], r["dst"]))
    if args.top:
        rows = rows[: args.top]

    # Regroupement par source pour affichage lisible
    by_src = defaultdict(list)
    for r in rows:
        by_src[r["src"]].append(r)

    for src, dsts in sorted(by_src.items()):
        src_tag = f"[{ip_type(src.split('/')[0]).upper()}]"
        print(f"\n{'='*72}")
        print(f"  SOURCE : {src}  {src_tag}")
        print(f"{'='*72}")
        for r in sorted(dsts, key=lambda x: -x["sessions"]):
            dst_tag = f"[{r['dst_type'].upper()}]"
            sessions_fmt = fmt_number(r["sessions"])
            bytes_fmt = fmt_bytes(r["bytes"])
            print(f"  → {r['dst']:<38} {dst_tag}")
            print(f"    Services : {r['services']}")
            print(f"    Sessions : {sessions_fmt}   Octets : {bytes_fmt}   Action : {r['action']}")

    print(f"\n{'─'*72}")
    print(f"  {len(rows)} paires source→destination")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def build_rows(flows: dict) -> list:
    rows = []
    for key, stats in flows.items():
        proto_name = PROTO_MAP.get(key.proto, key.proto)
        rows.append({
            "src":        key.src,
            "dst":        key.dst,
            "service":    key.service,
            "proto":      proto_name,
            "dstport":    key.dstport,
            "sessions":   stats.sessions,
            "sent_bytes": stats.sent_bytes,
            "rcvd_bytes": stats.rcvd_bytes,
            "bytes":      stats.total_bytes,
            "action":     stats.dominant_action,
        })
    return rows


def sort_rows(rows: list, args) -> list:
    key = args.sort
    reverse = True
    if key in ("src", "dst", "service", "action"):
        reverse = False
    try:
        return sorted(rows, key=lambda r: (r.get(key) or 0), reverse=reverse)
    except TypeError:
        return sorted(rows, key=lambda r: str(r.get(key) or ""), reverse=reverse)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="FortiFlow — Analyse de logs trafic FortiGate/FortiAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Vue tableau par défaut (sources privées uniquement)
  python fortiflow.py traffic.log

  # Export CSV de tous les flux
  python fortiflow.py traffic.log --output csv > flows.csv

  # Suggestions de politiques, regroupées par /24
  python fortiflow.py traffic.log --mode policy --subnet 24

  # Flux acceptés seulement, vers destinations publiques
  python fortiflow.py traffic.log --dst-only public --action accept

  # Top 20 flux les plus volumineux, regroupement /16
  python fortiflow.py traffic.log --mode subnet --subnet 16 --sort bytes --top 20

  # Plusieurs fichiers ou stdin
  python fortiflow.py *.log
  cat traffic.log | python fortiflow.py -
        """,
    )

    p.add_argument(
        "files",
        nargs="*",
        default=["-"],
        metavar="FILE",
        help="Fichier(s) de log (défaut: stdin). Supporte les wildcards.",
    )

    p.add_argument(
        "--mode",
        choices=["flow", "subnet", "policy"],
        default="flow",
        help=(
            "flow   : chaque IP individuelle (défaut)\n"
            "subnet : regroupe les IPs privées par sous-réseau (--subnet)\n"
            "policy : suggestions de règles groupées par paire src→dst"
        ),
    )

    p.add_argument(
        "--subnet",
        type=int,
        default=24,
        metavar="PREFIX",
        help="Longueur du masque pour le regroupement subnet (défaut: 24)",
    )

    p.add_argument(
        "--output",
        choices=["table", "csv", "policy"],
        default=None,
        help="Format de sortie (défaut: table, ou policy si --mode policy)",
    )

    p.add_argument(
        "--src-only",
        choices=["private", "public"],
        default="private",
        dest="src_only",
        help="Filtrer les sources : private (défaut) | public | (omis = toutes)",
    )

    p.add_argument(
        "--dst-only",
        choices=["private", "public"],
        default=None,
        dest="dst_only",
        help="Filtrer les destinations : private | public | (omis = toutes)",
    )

    p.add_argument(
        "--action",
        nargs="+",
        metavar="ACTION",
        help="Filtrer par action : accept deny close (plusieurs valeurs possibles)",
    )

    p.add_argument(
        "--vdom",
        nargs="+",
        metavar="VDOM",
        help="Filtrer par VDOM(s)",
    )

    p.add_argument(
        "--sort",
        default="sessions",
        choices=["sessions", "bytes", "src", "dst", "service", "action", "dstport"],
        help="Colonne de tri (défaut: sessions)",
    )

    p.add_argument(
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="Afficher seulement les N premiers résultats",
    )

    p.add_argument(
        "--all-src",
        action="store_true",
        dest="all_src",
        help="Inclure toutes les sources (public + private), équivalent à désactiver --src-only",
    )

    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Afficher les statistiques de parsing",
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --all-src écrase --src-only
    if args.all_src:
        args.src_only = None

    # Résoudre les wildcards shell si nécessaire (Windows)
    import glob as _glob
    resolved = []
    for f in args.files:
        if f == "-":
            resolved.append(f)
        else:
            expanded = _glob.glob(f)
            if expanded:
                resolved.extend(sorted(expanded))
            else:
                resolved.append(f)
    args.files = resolved

    # Mode de sortie par défaut
    output = args.output
    if output is None:
        output = "policy" if args.mode == "policy" else "table"

    # Agréger
    flows = aggregate(args.files, args)

    if not flows:
        print("Aucun flux trouvé avec ces critères.", file=sys.stderr)
        sys.exit(0)

    # Sortie
    if output == "csv":
        output_csv(flows, args)
    elif output == "policy":
        output_policy(flows, args)
    else:
        output_table(flows, args)


if __name__ == "__main__":
    main()
