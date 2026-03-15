# FortiFlow

Outil d'analyse de logs trafic **FortiGate / FortiAnalyzer** pour les prestations de segmentation réseau.

Analyse les flux, identifie les IPs privées (RFC1918), et agrège les communications pour faciliter la création de politiques de pare-feu.

- Aucune dépendance externe — stdlib Python 3.6+ uniquement
- Traitement en streaming : gère les fichiers de **200MB+** sans saturer la RAM
- Trois modes de sortie : tableau terminal, CSV (Excel), suggestions de politiques

---

## Usage rapide

```bash
# Vue tableau — sources privées vers toutes destinations
python fortiflow.py traffic.log

# Suggestions de politiques regroupées par /24 (le plus utile en presta)
python fortiflow.py traffic.log --mode policy --subnet 24

# Export CSV pour Excel
python fortiflow.py traffic.log --output csv > flows.csv

# Plusieurs fichiers d'un coup
python fortiflow.py log1.log log2.log log3.log --mode policy

# Depuis stdin (FortiAnalyzer export pipe)
cat traffic.log | python fortiflow.py -
```

---

## Modes

### `--mode flow` (défaut)
Chaque IP source individuelle avec chaque destination unique.
Utile pour voir exactement quelles machines communiquent avec quoi.

```
Source             Destination        Service   Sessions   Octets
192.168.10.15      192.168.20.10      HTTPS     2          232 KB
192.168.30.5       192.168.20.11      SSH       1          256 KB
10.0.0.5           192.168.20.10      RSYNC     1          100 MB
```

### `--mode subnet` / `--mode policy`
Regroupe les IPs privées par sous-réseau (`--subnet 24` par défaut).

**`policy`** affiche en plus les services agrégés par paire, prêt pour une revue de politique :

```
========================================================================
  SOURCE : 192.168.10.0/24  [PRIVATE]
========================================================================
  → 192.168.20.0/24                        [PRIVATE]
    Services : HTTPS, SAMBA
    Sessions : 4   Octets : 279 KB   Action : accept
  → 8.8.8.8                                [PUBLIC]
    Services : DNS
    Sessions : 1   Octets : 202 B   Action : accept
```

---

## Options complètes

| Option | Description | Défaut |
|--------|-------------|--------|
| `--mode flow\|subnet\|policy` | Mode d'agrégation | `flow` |
| `--subnet N` | Masque CIDR pour regroupement (/16, /24…) | `24` |
| `--output table\|csv\|policy` | Format de sortie | `table` (ou `policy` si mode policy) |
| `--src-only private\|public` | Filtrer les sources | `private` |
| `--dst-only private\|public` | Filtrer les destinations | toutes |
| `--all-src` | Inclure toutes les sources (désactive `--src-only`) | — |
| `--action accept deny close` | Filtrer par action (multi-valeur) | toutes |
| `--vdom VDOM1 VDOM2` | Filtrer par VDOM(s) | tous |
| `--sort sessions\|bytes\|src\|dst` | Colonne de tri | `sessions` |
| `--top N` | Afficher seulement les N premiers résultats | — |
| `-v / --verbose` | Statistiques de parsing | — |

---

## Exemples par cas d'usage

### Identifier les flux LAN → LAN (segmentation inter-VLAN)
```bash
python fortiflow.py traffic.log --src-only private --dst-only private --mode policy --subnet 24
```

### Identifier les flux LAN → Internet (règles NAT/accès web)
```bash
python fortiflow.py traffic.log --src-only private --dst-only public --mode policy
```

### Voir uniquement les flux refusés (deny) pour audit
```bash
python fortiflow.py traffic.log --action deny --mode flow --sort sessions
```

### Gros fichiers — top 50 flux par volume
```bash
python fortiflow.py big_export.log --sort bytes --top 50 --verbose
```

### Regroupement /16 pour un réseau très fragmenté
```bash
python fortiflow.py traffic.log --mode policy --subnet 16
```

### Export CSV + filtrage dans Excel
```bash
python fortiflow.py traffic.log --output csv --all-src > all_flows.csv
```

### Plusieurs exports FortiAnalyzer (même période)
```bash
python fortiflow.py export_jan_*.log --mode policy --subnet 24 --action accept
```

---

## Format des logs supportés

Format standard FortiGate `key=value` (export FortiOS / FortiAnalyzer) :

```
date=2024-01-15 time=08:12:34 devname="FGT-PROD" type="traffic" subtype="forward"
srcip=192.168.10.15 srcport=54321 dstip=192.168.20.10 dstport=443
proto=6 action="accept" service="HTTPS" sentbyte=15234 rcvdbyte=89012
```

Champs utilisés : `srcip`, `dstip`, `dstport`, `proto`, `service`, `action`, `sentbyte`, `rcvdbyte`, `vd`/`vdom`

---

## Fichier exemple

Un fichier `sample_traffic.log` est inclus pour tester rapidement :

```bash
python fortiflow.py sample_traffic.log --mode policy --subnet 24 --verbose
```
