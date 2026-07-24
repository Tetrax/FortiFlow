# FortiFlow

Outil d'analyse de logs trafic **FortiGate / FortiAnalyzer** pour les prestations de segmentation réseau.

FortiFlow importe les logs trafic, conserve leur contexte FortiGate/VDOM, construit les matrices de flux, rapproche les observations de la configuration et du routage, puis prépare une CLI FortiGate destinée à être revue par un ingénieur.

Le dépôt contient :

- l'application web Node.js dans `app/web`, utilisable via Docker ;
- le CLI Python historique `fortiflow.py`, sans dépendance externe ;
- les exports CSV/XLSX et les suggestions de politiques.

## Invariants de sécurité

La génération suit un modèle **fail closed** :

- seules les actions FortiOS explicitement reconnues comme autorisées produisent des suggestions ;
- les actions inconnues sont comptées mais exclues des règles ;
- les équipements et VDOM ne sont jamais fusionnés silencieusement ;
- une destination WAN reste limitée aux IP observées ; `dstaddr "all"` nécessite un choix explicite ;
- les couples protocole/port/service sont conservés sans troncature ;
- un objet service existant n'est réutilisé que si ses protocoles et ports sont
  exactement égaux aux tuples observés ; sinon un objet exact est proposé ;
- aucun repli implicite vers `service ALL` ou `srcaddr all` n'est autorisé ;
- les flux locaux, NATés, sans preuve de chemin forward ou dont le protocole est
  seulement déduit restent visibles mais ne produisent pas de règles ;
- une sélection de route ECMP ambiguë n'est pas résolue arbitrairement ;
- les routes désactivées sont ignorées et l'ordre first-match des policies existantes est conservé ;
- une VRF non par défaut bloque la génération tant que ce contexte n'est pas sélectionnable ;
- la présence d'IPv6 non analysé, d'actions inconnues, de lignes trafic invalides,
  d'une archive partielle ou de plusieurs équipements/VDOM bloque la génération ;
- le serveur exécute systématiquement le preflight avant toute génération CLI.

Le preflight distingue deux résultats :

- **exact** : source `/32`, destination `/32`, un service par règle et chaque
  tuple hôte/hôte/service est prouvé par les logs ;
- **généralisé** : un réseau ou plusieurs services sont volontairement regroupés.
  La règle peut être valide, mais elle autorise par construction un périmètre plus
  large que les seuls tuples observés et ne doit pas être présentée comme « exacte ».

Les réseaux RFC1918 sont internes par défaut. Un préfixe public porté par une interface LAN de la configuration sélectionnée est également classé comme interne.

> L'application ne remplace pas la validation d'un ingénieur FortiGate. Vérifier la période de capture, les flux saisonniers, le routage/PBR, les objets dynamiques, les VIP, le NAT central et l'ordre final des policies avant déploiement. L'instance est prévue pour un environnement interne de confiance.

## Vérification

Les tests ne nécessitent aucun service externe :

```bash
cd app/web
npm test
```

GitHub Actions vérifie également la syntaxe JavaScript et les invariants de sécurité à chaque modification de `main`.

## Architecture du traitement

Le serveur HTTP reste disponible pendant les imports volumineux :

- l’upload est écrit sur disque en streaming ;
- le parsing et la construction de la matrice s’exécutent dans un worker Node.js isolé ;
- une file d’attente bornée empêche plusieurs exports FAZ de saturer la mémoire ;
- les résultats conservent exactement le même format de session et de workspace.

Variables Docker :

| Variable | Rôle | Défaut |
|----------|------|--------|
| `MAX_ANALYSIS_WORKERS` | Analyses simultanées | `1` |
| `MAX_ANALYSIS_QUEUE` | Fichiers supplémentaires en attente | `3` |
| `ANALYSIS_WORKER_MEMORY_MB` | Plafond mémoire par worker, `0` pour la limite Node | `0` |

Pour des fichiers proches de 1–2 Go, conserver un seul worker est recommandé afin de privilégier la stabilité du VPS.

---

## Usage rapide du CLI Python

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

Champs de preuve recommandés : `type=traffic`, `subtype=forward`, `srcip`,
`dstip`, `srcintf`, `dstintf`, `policyid`, `dstport`, `proto`, `service`,
`action`, `sentbyte`, `rcvdbyte`, `devname`/`devid` et `vd`/`vdom`.

Un export sans protocole explicite, sans contexte forward ou contenant une
traduction NAT reste analysable, mais il n'est pas certifiable pour produire du CLI.

---

## Fichier exemple

Un fichier `sample_traffic.log` est inclus pour tester rapidement :

```bash
python fortiflow.py sample_traffic.log --mode policy --subnet 24 --verbose
```

---

## Déploiement Docker

### Prérequis

| Composant | Version minimum | Testé avec |
|-----------|----------------|------------|
| Docker Engine | 20.10+ | 29.2.1 |
| Docker Compose plugin | v2.0+ | v5.1.0 |
| Node.js *(hors Docker)* | 18 LTS+ | 22.x |

> L'image embarque Node.js 20 LTS — aucune installation Node requise si tu passes par Docker.

### Lancer en local (test rapide)

```bash
docker compose up --build -d
# Interface disponible sur http://localhost:3737
```

### Arrêter / relancer

```bash
docker compose down        # arrêt propre (données conservées dans ./data/)
docker compose up -d       # redémarrage sans rebuild
docker compose up --build -d  # rebuild + redémarrage (après mise à jour du code)
```

Les données persistantes (sessions, workspaces) sont stockées dans `./data/` à la racine du projet.

---

## Migration vers une autre machine

### 1. Prérequis sur la machine cible (Debian)

```bash
# Docker Engine + Compose plugin
apt update && apt install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Vérification
docker --version && docker compose version
```

### 2. Transférer le projet

```bash
# Sur la machine source — créer une archive du projet
# (adapter le chemin si le projet n'est pas dans ~/workspace)
cd ~/workspace   # ou /opt, /home/user, peu importe
tar --exclude='FortiFlow/app/web/node_modules' \
    --exclude='FortiFlow/.git' \
    --exclude='FortiFlow/app/web/uploads' \
    -czf fortiflow-transfer.tar.gz FortiFlow/

# Copier vers la machine cible
scp fortiflow-transfer.tar.gz user@IP_CIBLE:/opt/
```

### 3. Déployer sur la machine cible

```bash
# Sur la machine cible
cd /opt
tar -xzf fortiflow-transfer.tar.gz
cd FortiFlow

# Construire l'image et démarrer
docker compose up --build -d

# Vérifier que le conteneur tourne
docker compose ps
docker compose logs -f
```

L'interface est accessible sur `https://IP_CIBLE` une fois les certificats en place (voir étape 5).

### 4. Migrer les données existantes (optionnel)

Si tu veux conserver les sessions et workspaces de l'ancienne machine :

```bash
# Sur la machine source
tar -czf fortiflow-data.tar.gz FortiFlow/data/

# Copier vers la machine cible
scp fortiflow-data.tar.gz user@IP_CIBLE:/opt/

# Sur la machine cible (avant de démarrer Docker)
cd /opt
tar -xzf fortiflow-data.tar.gz
```

### 5. HTTPS (réseau interne / PKI d'entreprise)

Le `docker-compose.yml` est préconfiguré pour HTTPS sur le port 443. Il suffit de placer les certificats dans `/etc/ssl/fortiflow/` sur la machine hôte.

**Structure attendue :**
```
/etc/ssl/fortiflow/
├── privkey.pem      ← clé privée
└── fullchain.pem    ← certificat + chaîne intermédiaire
```

**Option A — PKI interne (AD CS, EJBCA, etc.) :**
Signer une CSR pour le CN/SAN de la machine et déposer les fichiers ci-dessus.

**Option B — `mkcert` (certificat reconnu sur le parc local) :**
```bash
# Sur le poste admin
mkcert -install                        # installe la CA locale (une seule fois)
mkcert <IP_OU_HOSTNAME>                # génère privkey.pem + fullchain.pem
mkdir -p /etc/ssl/fortiflow
cp <IP_OU_HOSTNAME>-key.pem /etc/ssl/fortiflow/privkey.pem
cp <IP_OU_HOSTNAME>.pem     /etc/ssl/fortiflow/fullchain.pem
```

**Option C — Self-signed (si aucune PKI disponible) :**
```bash
mkdir -p /etc/ssl/fortiflow
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout /etc/ssl/fortiflow/privkey.pem \
  -out    /etc/ssl/fortiflow/fullchain.pem \
  -subj "/CN=fortiflow" \
  -addext "subjectAltName=IP:<IP_MACHINE>"
```

**Démarrer après avoir placé les certificats :**
```bash
docker compose up --build -d
# Interface disponible sur https://IP_CIBLE
```

> Le serveur détecte automatiquement la présence des certificats au démarrage.
> S'ils sont absents, il bascule en HTTP sur le même port (utile pour un premier test).
