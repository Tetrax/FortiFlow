# FortiFlow — Guide de déploiement

## Scénarios couverts

| Scénario | Certificats | Reverse proxy | Orchestrateur |
|----------|-------------|---------------|---------------|
| **VPS (Let's Encrypt)** | Let's Encrypt → `/etc/ssl/fortiflow/` | Nginx hôte | `docker compose` |
| **Interne (wildcard CA)** | Certificat wildcard PKI interne → `/etc/ssl/fortiflow/` | Nginx hôte | Portainer |
| **Interne (self-signed)** | `mkcert` ou `openssl` | Nginx hôte | Portainer |

Dans tous les cas, FortiFlow écoute sur `127.0.0.1:13737` et le reverse proxy (Nginx) expose le HTTPS sur `443`.

---

## 1. Prérequis communs

```bash
# Structure des certificats attendue sur l'hôte
/etc/ssl/fortiflow/
├── privkey.pem      # Clé privée
└── fullchain.pem    # Certificat + chaîne intermédiaire
```

---

## 2. Certificats — 3 options

### Option A : Let's Encrypt (VPS)

```bash
# Certbot doit déjà être configuré. Créer un hook de déploiement.
sudo mkdir -p /etc/ssl/fortiflow
sudo cp /etc/letsencrypt/live/<DOMAINE>/privkey.pem   /etc/ssl/fortiflow/privkey.pem
sudo cp /etc/letsencrypt/live/<DOMAINE>/fullchain.pem /etc/ssl/fortiflow/fullchain.pem
sudo chmod 600 /etc/ssl/fortiflow/*.pem

# Optionnel : hook automatique après renouvellement
# Ajouter dans /etc/letsencrypt/renewal-hooks/deploy/fortiflow.sh :
#   #!/bin/bash
#   cp /etc/letsencrypt/live/$RENEWED_DOMAIN/privkey.pem   /etc/ssl/fortiflow/privkey.pem
#   cp /etc/letsencrypt/live/$RENEWED_DOMAIN/fullchain.pem /etc/ssl/fortiflow/fullchain.pem
#   docker restart fortiflow
```

### Option B : Certificat wildcard interne (PKI entreprise)

```bash
# Récupérer le certificat wildcard depuis la PKI interne (AD CS, EJBCA, etc.)
# Format attendu : clé privée PEM + certificat + chaîne

sudo mkdir -p /etc/ssl/fortiflow
sudo cp wildcard.key  /etc/ssl/fortiflow/privkey.pem
sudo cp wildcard.crt  /etc/ssl/fortiflow/fullchain.pem
sudo chmod 600 /etc/ssl/fortiflow/*.pem
```

### Option C : Self-signed (test/local)

```bash
sudo mkdir -p /etc/ssl/fortiflow
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout /etc/ssl/fortiflow/privkey.pem \
  -out    /etc/ssl/fortiflow/fullchain.pem \
  -subj  "/CN=fortiflow" \
  -addext "subjectAltName=IP:<IP_SERVEUR>,DNS:fortiflow.local"
```

---

## 3. Déploiement VPS (docker compose)

```bash
cd ~/workspace/FortiFlow
git pull

# Créer le .env (ou utiliser les valeurs par défaut)
cp .env.example .env
# Éditer .env si besoin : DOMAIN, MAX_UPLOAD_SIZE_MB, etc.

# Variables SSL dans .env :
#   SSL_KEY=/certs/privkey.pem
#   SSL_CERT=/certs/fullchain.pem

docker compose up --build -d
docker compose ps
docker compose logs -f
```

---

## 4. Déploiement Portainer (serveur interne)

### 4.1 Première installation

1. **Builder l'image** (sur une machine avec accès internet) :
   ```bash
   cd ~/workspace/FortiFlow/app/web
   docker build -t fortiflow-fortiflow:latest .
   docker save fortiflow-fortiflow:latest -o fortiflow.tar
   ```

2. **Transférer l'image** sur le serveur interne :
   ```bash
   scp fortiflow.tar user@SERVEUR_INTERNE:/tmp/
   ```

3. **Importer l'image** sur le serveur interne :
   ```bash
   docker load -i /tmp/fortiflow.tar
   ```

4. **Préparer les certificats** (Option B ou C ci-dessus).

5. **Dans Portainer** :
   - Aller dans **Stacks → Add stack**
   - Nom : `fortiflow`
   - Uploader ou coller le contenu de `docker-compose.portainer.yml`
   - Définir les variables d'environnement si besoin
   - **Deploy the stack**

### 4.2 Mise à jour (après modifications du code)

```bash
# Sur la machine de build
cd ~/workspace/FortiFlow
git pull
cd app/web
docker build -t fortiflow-fortiflow:latest .
docker save fortiflow-fortiflow:latest -o fortiflow.tar
scp fortiflow.tar user@SERVEUR_INTERNE:/tmp/

# Sur le serveur interne
docker load -i /tmp/fortiflow.tar

# Dans Portainer :
# 1. Stacks → fortiflow → Stop this stack
# 2. (Optionnel) Modifier les variables si nécessaire
# 3. Start the stack (l'image :latest sera utilisée automatiquement)
```

### 4.3 Alternative : GitHub Container Registry

Si le serveur interne a accès à Internet :

1. Modifier `docker-compose.portainer.yml` pour utiliser `image: ghcr.io/tetrax/fortiflow:latest`
2. Dans Portainer, ajouter le registry GitHub :
   - **Registries → Add registry**
   - Provider : GitHub
   - Username : `Tetrax`
   - Token : PAT avec scope `read:packages`
3. Déployer la stack — l'image sera pullée automatiquement

---

## 5. Reverse proxy Nginx

```bash
# Copier la configuration
sudo cp infra/nginx/fortiflow.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/fortiflow.conf /etc/nginx/sites-enabled/

# Adapter le server_name et les chemins de certificats
sudo vim /etc/nginx/sites-available/fortiflow.conf

# Vérifier et recharger
sudo nginx -t
sudo systemctl reload nginx
```

Configuration Nginx fournie dans `infra/nginx/fortiflow.conf`.

---

## 6. Vérification

```bash
# Container healthy ?
docker ps --filter name=fortiflow
# Doit afficher "(healthy)"

# Logs
docker logs fortiflow --tail 20
# Devrait afficher : FortiFlow → https://...

# Test HTTPS (depuis l'hôte ou un poste client)
curl -k https://localhost/
curl -k https://<IP_SERVEUR>/
```

---

## 7. Backup et restauration

```bash
# Backup
tar -czf fortiflow-backup-$(date +%Y%m%d).tar.gz \
  /home/tetrax/workspace/FortiFlow/data/

# Restauration
cd /home/tetrax/workspace/FortiFlow
tar -xzf fortiflow-backup-YYYYMMDD.tar.gz
docker compose up -d   # ou redeploy via Portainer
```

---

## 8. Résolution de problèmes

| Symptôme | Cause probable | Solution |
|----------|---------------|----------|
| Container `unhealthy` | Node.js ne répond pas | `docker logs fortiflow` |
| HTTP mais pas HTTPS | Certificats absents ou mal montés | Vérifier `/etc/ssl/fortiflow/` |
| `Permission denied` sur `/certs` | Les fichiers n'ont pas les bons droits | `chmod 644` sur les .pem |
| Portainer : `no such image` | Image non importée | `docker load -i fortiflow.tar` |
| Nginx : 502 Bad Gateway | FortiFlow ne tourne pas | Vérifier `docker ps` |
