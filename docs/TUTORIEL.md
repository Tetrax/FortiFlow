# Guide de Déploiement — FortiFlow

Version 2.0 — 3 août 2026 — Revue et corrigé par Da Vinci (QA)

CI : VERTE (4/4) | Déploiement : Portainer | Image : ghcr.io/tetrax/fortiflow:latest

Ce guide explique pas à pas comment déployer l'application sur la VM de production. L'application sera accessible en HTTPS sur le réseau interne à l'adresse **https://fortiflow.monentreprise.lan.**

| ■ Machine | ■ Où ? | ■ Qui ? | ■ Accès |
|---|---|---|---|
| SOURCE (dev) | VPS IONOS | Da Vinci (Hermes) | Automatique (CI/CD) |
| DESTINATION (prod) | VM Entreprise | Valentin | Console/SSH (root) |

> ■ **Déploiement interne uniquement.** L'application ne sera PAS exposée sur Internet. Certificat TLS : PKI entreprise. Nom de domaine : **fortiflow.monentreprise.lan.**

---

## 1. Préparer les éléments nécessaires

### Machine cible

La VM de production doit disposer de :

- Docker (≥ 24.0) installé et fonctionnel ;
- Portainer Community Edition accessible sur le port 9443 ;
- une adresse IP LAN fixe ;
- un accès SSH root pour les commandes d'installation ;
- des règles firewall limitant le port 13737 aux réseaux internes autorisés.

### Droits d'accès

- Accès à la console Portainer avec un compte administrateur ;
- Accès SSH root sur la VM de production ;
- Connexion au réseau interne de l'entreprise.

### Image Docker

L'image Docker est déjà buildée par la CI. **Aucune construction manuelle n'est nécessaire.**

- Registre : `ghcr.io`
- Image : `ghcr.io/tetrax/fortiflow:latest`

> ■ L'image est publique. **Rien à builder.** Le déploiement se fait intégralement via Portainer en mode Repository.

---

## 2. Présentation du projet

**FortiFlow** est un outil d'analyse de logs trafic **FortiGate / FortiAnalyzer** pour les prestations de segmentation réseau. Il importe les logs trafic, conserve leur contexte FortiGate/VDOM, construit les matrices de flux, rapproche les observations de la configuration et du routage, puis prépare une CLI FortiGate destinée à être revue par un ingénieur.

### Architecture

Un seul conteneur Docker : **fortiflow** (Node.js + Express, port interne 3737).

```
┌─────────────────────────────────────┐
│           VM de production          │
│  ┌───────────────────────────────┐  │
│  │       Portainer (9443)        │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │   Stack fortiflow       │  │  │
│  │  │  ┌───────────────────┐  │  │  │
│  │  │  │  fortiflow:latest │  │  │  │
│  │  │  │  (port 3737)      │  │  │  │
│  │  │  └───────────────────┘  │  │  │
│  │  └─────────────────────────┘  │  │
│  │          ▲                     │  │
│  │          │ Nginx (443)         │  │
│  └──────────┼─────────────────────┘  │
│             │ port 13737             │
└─────────────┼────────────────────────┘
              │
     Réseau interne (LAN)
              │
     https://fortiflow.monentreprise.lan
```

### Variables d'environnement principales

| Variable | Valeur par défaut | Description |
|---|---|---|
| PORT | 3737 | Port interne du conteneur |
| DOMAIN | devval.com | Domaine de l'application |
| MAX_UPLOAD_SIZE_MB | 2048 | Taille max d'upload (Mo) |
| MAX_DECOMPRESSED_SIZE_MB | 4096 | Taille max après décompression (Mo) |
| MAX_ARCHIVE_ENTRIES | 100 | Nombre max d'entrées dans une archive |
| MAX_XLSX_SIZE_MB | 100 | Taille max XLSX (Mo) |
| MAX_WORKSPACE_UNCOMPRESSED_MB | 1024 | Taille max workspace (Mo) |
| MAX_SESSION_DEDUPE_KEYS | 2000000 | Max clés de déduplication par session |
| MAX_ANALYSIS_WORKERS | 1 | Workers d'analyse parallèles |
| MAX_ANALYSIS_QUEUE | 3 | File d'attente d'analyse |
| ANALYSIS_WORKER_MEMORY_MB | 0 | Mémoire par worker (0 = auto) |

> ■ Les variables `SSL_KEY` et `SSL_CERT` sont optionnelles. Elles ne sont nécessaires que pour l'Option B (TLS géré par l'application, voir section 11).

---

## 3. Revue de code synthétique

Revue réalisée le 3 août 2026 par l'équipe Da Vinci (Socrate, Archimède, Ada). 49 tests passent, 0 échec.

| ■ Correction | ■ Impact |
|---|---|
| `node:20-alpine` → `node:22-alpine` | 47 CVE corrigées |
| Ajout `healthcheck` Docker | Monitoring de santé du conteneur |
| `security_opt` + `tmpfs /tmp` | Durcissement sécurité |
| Rate limiting token-bucket sur `/api/upload` + `/api/admin` | Protection brute-force |
| Graceful shutdown (`SIGTERM`/`SIGINT`) | Arrêt propre avec fermeture du pool |
| Module partagé `lib/constants.js` | Déduplication `ALLOW_ACTIONS` / `DENY_ACTIONS` |
| Suppression `ecosystem.config.js` | Fichier mort (PM2 non utilisé) |
| CI : build Docker + scan Trivy + push GHCR | Pipeline de sécurité complet |
| `.env.example` + config Nginx | Documentation des variables et reverse proxy |

---

## 4. Connexion à la VM de production

### 4.1 Ouvrir une session SSH

Se connecter en **root** sur la VM de l'entreprise où tourne Portainer.

```bash
# Depuis ton poste :
ssh root@ADRESSE_IP_DE_LA_VM
```

### 4.2 Vérifier Portainer

```bash
docker ps | grep portainer
# → Doit afficher une ligne
```

### 4.3 Vérifier Docker

```bash
docker version
# → Doit être ≥ 24.0
```

---

## 5. Création des répertoires persistants

### 5.1 Pourquoi ?

Les conteneurs sont éphémères. Les données doivent survivre aux mises à jour → on crée des répertoires montés.

### 5.2 Création et permissions

```bash
mkdir -p /srv/fortiflow/data /srv/fortiflow/certificates
chown -R 1000:1000 /srv/fortiflow
```

### 5.3 Vérification

```bash
ls -la /srv/fortiflow/
# Doit afficher data/ certificates/ avec 1000:1000
```

> ■ Si Docker utilise un UID différent : exécuter `id docker` pour trouver le bon.

---

## 6. Vérification du port 13737

### 6.1 Pourquoi ?

L'application utilise le port **13737** en externe (mappé vers 3737 dans le conteneur). On vérifie qu'il est libre.

### 6.2 Vérification

```bash
ss -tlnp | grep 13737
# RIEN affiché → OK. Sinon → choisir un autre port.
```

> ■ Si le port est occupé, modifier le mapping dans le fichier `docker-compose.portainer.yml` avant de créer le stack.

---

## 7. Déployer le stack dans Portainer

### 7.1 Méthode de déploiement

Le déploiement utilise le mode **Repository** de Portainer. L'image est automatiquement téléchargée depuis `ghcr.io/tetrax/fortiflow:latest`.

Ne pas utiliser le mode Upload ni importer d'archive `.tar`.

### 7.2 Ouvrir Portainer

```
https://ADRESSE_IP_DE_LA_VM:9443
# Se connecter avec un compte administrateur
```

### 7.3 Créer le stack

1. Menu gauche → **Stacks**
2. Cliquer sur **+ Add stack**
3. Saisir le nom :
   ```
   fortiflow
   ```
4. Build method : **Repository**
5. Saisir les informations du dépôt :
   ```
   Repository URL       : https://github.com/Tetrax/FortiFlow
   Repository reference : refs/heads/main
   Compose path         : docker-compose.portainer.yml
   ```

Le fichier `docker-compose.portainer.yml` référence directement l'image **ghcr.io/tetrax/fortiflow:latest** — Portainer la télécharge automatiquement lors du déploiement.

### 7.4 Variables d'environnement

Dans la section **Environment variables**, cliquer sur **+ Add environment variable** pour chaque ligne :

```
Nom                                  Valeur
──────────────────────────────────────────────────────────
PORT                                 3737
DOMAIN                               devval.com
MAX_UPLOAD_SIZE_MB                   2048
MAX_DECOMPRESSED_SIZE_MB             4096
MAX_ARCHIVE_ENTRIES                  100
MAX_XLSX_SIZE_MB                     100
MAX_WORKSPACE_UNCOMPRESSED_MB        1024
MAX_SESSION_DEDUPE_KEYS              2000000
MAX_ANALYSIS_WORKERS                 1
MAX_ANALYSIS_QUEUE                   3
ANALYSIS_WORKER_MEMORY_MB            0
```

> ■ Ne pas ajouter `SSL_KEY` ni `SSL_CERT` à ce stade. Ces variables seront ajoutées uniquement si l'Option B (TLS géré par l'application, section 11) est retenue.

### 7.5 Déployer

Cliquer **Deploy the stack**. Portainer :
1. Télécharge l'image depuis `ghcr.io/tetrax/fortiflow:latest`
2. Crée le conteneur `fortiflow`
3. Démarre le conteneur

Le déploiement prend environ 15 secondes.

---

## 8. Vérifier le fonctionnement initial en HTTP

### 8.1 Vérification dans Portainer

Ouvrir **Containers** → le conteneur doit être **running (healthy)** :

```
fortiflow          running (healthy)
```

### 8.2 Vérification depuis le terminal SSH

```bash
docker ps --filter "name=fortiflow"
```

Identifier le conteneur et vérifier son statut :

```bash
CONTAINER="$(docker ps --filter name=fortiflow --format '{{.Names}}')"
printf 'Conteneur : %s\n' "$CONTAINER"
```

Contrôler les logs :

```bash
docker logs --tail 50 "$CONTAINER"
```

Tester l'application :

```bash
curl -s http://localhost:13737/ | head -10
# → Doit afficher du HTML avec "FortiFlow"
```

Vérifier le healthcheck :

```bash
docker inspect --format '{{.State.Health.Status}}' "$CONTAINER"
# → healthy
```

### 8.3 Vérification depuis un navigateur (réseau interne)

```
http://ADRESSE_IP_DE_LA_VM:13737
# → Dashboard FortiFlow
```

À ce stade, le port 13737 doit être accessible uniquement depuis les VLAN ou sous-réseaux internes autorisés. Il ne doit jamais être publié sur Internet.

---

## 9. Préparer le certificat TLS

### 9.1 Contexte

L'URL finale sera : **https://fortiflow.monentreprise.lan**

Le certificat est fourni par la **PKI interne** de l'entreprise (AD CS, EJBCA, etc.). **Pas de Let's Encrypt.**

### 9.2 SAN requis

Le certificat doit contenir dans ses SAN DNS :

```
fortiflow.monentreprise.lan
```

Un wildcard peut être utilisé :

```
*.monentreprise.lan
```

Ce wildcard couvre par exemple `fortiflow.monentreprise.lan`, mais ne couvre pas `monentreprise.lan` seul.

### 9.3 Obtenir le certificat

Demander à l'équipe IT les deux fichiers pour **fortiflow.monentreprise.lan** (ou wildcard `*.monentreprise.lan`) :

1. Certificat public : `fortiflow.lan.crt`
2. Clé privée : `fortiflow.lan.key`

> ■ Ne jamais ajouter ces fichiers, les clés privées ou leurs mots de passe dans Git.

### 9.4 Transférer les fichiers vers la VM

```bash
scp fortiflow.lan.crt root@VM_IP:/srv/fortiflow/certificates/
scp fortiflow.lan.key root@VM_IP:/srv/fortiflow/certificates/
```

### 9.5 Placer les certificats

```bash
cd /srv/fortiflow/certificates
ls -la  # Doit afficher fortiflow.lan.crt et fortiflow.lan.key
chmod 600 fortiflow.lan.key
chmod 644 fortiflow.lan.crt
chown -R 1000:1000 /srv/fortiflow/certificates
```

---

## 10. Option A — HTTPS avec Nginx (recommandé)

### 10.1 Installer Nginx si nécessaire

```bash
apt update && apt install -y nginx
```

### 10.2 Créer la configuration Nginx

```bash
nano /etc/nginx/sites-available/fortiflow
```

Coller le contenu suivant :

```nginx
server {
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
}
```

### 10.3 Activer le site

```bash
ln -s /etc/nginx/sites-available/fortiflow /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### 10.4 DNS interne

Demander à l'équipe IT un enregistrement DNS interne :

```
fortiflow.monentreprise.lan → IP_VM
```

> ■ **En attendant** : ajouter `IP_VM fortiflow.monentreprise.lan` dans `/etc/hosts` du poste de test.

---

## 11. Option B — HTTPS sans Nginx (TLS géré par l'application)

### 11.1 Contexte

Avec cette option, l'application gère elle-même le TLS. Le serveur Node.js écoute directement en HTTPS sur le port 13737.

> ■■ **Avec TLS direct, l'application écoute en HTTPS sur le port 13737 (plus HTTP). Le test curl doit devenir : `curl -k https://localhost:13737`.**

### 11.2 Placer les certificats pour l'application

Les certificats doivent être au format PEM :

```bash
mkdir -p /etc/ssl/fortiflow/
cp /srv/fortiflow/certificates/fortiflow.lan.crt /etc/ssl/fortiflow/fullchain.pem
cp /srv/fortiflow/certificates/fortiflow.lan.key /etc/ssl/fortiflow/privkey.pem
chmod 644 /etc/ssl/fortiflow/fullchain.pem
chmod 600 /etc/ssl/fortiflow/privkey.pem
chown -R 1000:1000 /etc/ssl/fortiflow/
```

### 11.3 Ajouter les variables SSL dans Portainer

Dans le stack Portainer, section **Environment variables**, ajouter :

```
SSL_KEY=/certs/privkey.pem
SSL_CERT=/certs/fullchain.pem
```

### 11.4 Redéployer

Dans Portainer : **Stacks → fortiflow → Pull and redeploy → Update**.

Le conteneur monte `/etc/ssl/fortiflow/` en `/certs/` (lecture seule). Le serveur détecte automatiquement la présence des certificats et bascule en HTTPS.

> ■ Les variables `SSL_KEY` et `SSL_CERT` sont déjà référencées dans le compose. Ne pas les dupliquer dans Portainer sauf si tu les surcharges.

---

## 12. Vérifier le fonctionnement en HTTPS

### 12.1 Vérification dans Portainer

Ouvrir **Containers** → le conteneur `fortiflow` doit être **running (healthy)**.

### 12.2 Vérification depuis le terminal SSH

```bash
# Option A (Nginx) :
curl -k https://localhost/
# → Dashboard FortiFlow

# Option B (TLS direct) :
curl -k https://localhost:13737/
# → Dashboard FortiFlow
```

### 12.3 Vérification depuis un navigateur

```
https://fortiflow.monentreprise.lan
# → Dashboard en HTTPS, cadenas vert (PKI entreprise reconnue)
```

L'absence d'alerte nécessite :
- un SAN DNS correct ;
- une chaîne de certificats correcte ;
- une CA interne installée dans le magasin de confiance du poste.

### 12.4 Vérifier que HTTP n'est plus exposé

```bash
# Option A : le port 13737 ne doit plus être accessible directement
curl --max-time 3 http://IP_LAN_VM:13737/ && echo 'ERREUR' || echo 'OK'

# Option B : idem
curl --max-time 3 http://IP_LAN_VM:13737/ && echo 'ERREUR' || echo 'OK'
```

Une fois HTTPS validé, ne plus exposer HTTP sur le réseau.

---

## 13. Mise à jour future

### 13.1 Portainer (recommandé)

Dans Portainer :
1. Ouvrir **Stacks**
2. Sélectionner `fortiflow`
3. Cliquer sur **Pull and redeploy**
4. **Update**

Portainer télécharge `ghcr.io/tetrax/fortiflow:latest` et redémarre le conteneur. L'interruption de service est d'environ 5 secondes.

Ne pas supprimer les volumes pendant la mise à jour.

### 13.2 SSH (plan B)

```bash
cd /srv/fortiflow
docker compose -f docker-compose.portainer.yml pull
docker compose -f docker-compose.portainer.yml up -d
```

Le compose référence directement `ghcr.io` → `docker compose pull` fonctionne.

---

## 14. Dépannage

| ■ Problème | ■ Vérification / Action |
|---|---|
| Stack ne se déploie pas | Vérifier toutes les variables d'environnement : PORT, DOMAIN, MAX_UPLOAD_SIZE_MB, etc. |
| Conteneur en erreur | `chown -R 1000:1000 /srv/fortiflow` puis `docker logs fortiflow` |
| Statut healthy absent | Vérifier que le healthcheck est présent dans le compose |
| HTTPS ne fonctionne pas (Option A) | Vérifier les chemins dans Nginx, `nginx -t`, vérifier le DNS interne |
| HTTPS ne fonctionne pas (Option B) | Vérifier que SSL_KEY et SSL_CERT pointent sur les bons fichiers dans /certs/ |
| Certificat non reconnu | Vérifier que le poste fait confiance à la CA racine de l'entreprise |
| Dashboard page blanche | `docker logs fortiflow --tail 50`, vérifier les variables d'environnement |
| Erreur `ANALYSIS_CANCELLED` | Analyse interrompue — relancer l'upload |
| Erreur `DECOMPRESSED_SIZE_LIMIT` | Archive trop volumineuse — augmenter `MAX_DECOMPRESSED_SIZE_MB` |
| Portainer : `no such image` | Utiliser la méthode Repository (pas d'import manuel) |
| Permission denied sur /certs | `chmod 644` sur les .pem dans `/etc/ssl/fortiflow/` |
| Le navigateur affiche une alerte | Vérifier la résolution DNS, le FQDN dans l'URL, le SAN du certificat, la chaîne envoyée |

---

## 15. Checklist finale

Le déploiement est terminé lorsque tous les points suivants sont validés :

- [ ] `/srv/fortiflow/data` et `/srv/fortiflow/certificates` créés avec permissions `1000:1000`
- [ ] Port `13737` libre sur la VM
- [ ] Stack Portainer `fortiflow` déployé en mode Repository
- [ ] Image `ghcr.io/tetrax/fortiflow:latest` téléchargée automatiquement
- [ ] Conteneur `fortiflow` est **healthy**
- [ ] `curl http://localhost:13737/` répond depuis la VM
- [ ] Dashboard accessible depuis le réseau interne en HTTP (étape 8)
- [ ] Certificat TLS obtenu auprès de l'équipe IT (SAN : `fortiflow.monentreprise.lan`)
- [ ] Certificats placés dans `/srv/fortiflow/certificates/` avec permissions correctes
- [ ] Option A : Nginx configuré et actif sur le port 443
- [ ] Option B : variables `SSL_KEY` et `SSL_CERT` configurées, certificats dans `/etc/ssl/fortiflow/`
- [ ] DNS interne créé : `fortiflow.monentreprise.lan → IP_VM`
- [ ] `https://fortiflow.monentreprise.lan` accessible, cadenas vert
- [ ] HTTP n'est plus exposé
- [ ] Le firewall limite l'accès aux réseaux internes autorisés
- [ ] Aucun secret ou clé privée n'est stocké dans Git ou dans l'image

■ **Déploiement terminé. Application accessible en HTTPS sur le réseau interne.** ■

---

### ■ Ressources

- **Repo :** https://github.com/Tetrax/FortiFlow
- **Image :** ghcr.io/tetrax/fortiflow:latest
- **CI :** https://github.com/Tetrax/FortiFlow/actions
