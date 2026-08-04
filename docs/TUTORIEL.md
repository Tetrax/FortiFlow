# FortiFlow — Guide opérationnel

> Déploiement initial et mise à jour avec Portainer Repository, image GHCR et HTTPS interne.

Image : `ghcr.io/tetrax/fortiflow:latest`
Stack : `fortiflow`
Dépôt public : `https://github.com/Tetrax/FortiFlow`

## 1. Prérequis

### Accès et composants

- VM Linux avec Docker 24 ou plus récent.
- Portainer Community Edition accessible avec un compte administrateur.
- Accès SSH administrateur à la VM.
- Accès sortant vers GitHub et `ghcr.io`.
- Adresse IP fixe et, pour HTTPS, un nom DNS interne.

### Paramètres de référence

| Élément | Valeur |
|---|---|
| Dépôt | `https://github.com/Tetrax/FortiFlow` |
| Branche | `refs/heads/main` |
| Compose | `docker-compose.portainer.yml` |
| Image | `ghcr.io/tetrax/fortiflow:latest` |
| Service | `fortiflow` |
| Port interne | `3737` |
| Port hôte HTTP | `127.0.0.1:13737` |

> Le dépôt et l’image sont publics. Ne pas construire l’image sur la VM et ne pas importer de fichier TAR.

## 2. Préparer le serveur cible

### Vérifier Docker et Portainer

```bash
docker version
docker ps --filter name=portainer
```

Docker doit répondre et Portainer doit être en cours d’exécution.

### Préparer les certificats

Le compose monte `/etc/ssl/fortiflow` dans le conteneur. Le laisser vide pour le premier démarrage HTTP.

```bash
mkdir -p /etc/ssl/fortiflow /srv/fortiflow/certificates
chmod 700 /etc/ssl/fortiflow /srv/fortiflow/certificates
```

Les volumes applicatifs sont créés automatiquement par Docker. Ne pas les supprimer lors d’une mise à jour.

### Vérifier les ports

```bash
ss -tlnp | grep -E ':(13737|443)\b' || true
```

Le port `13737` doit être libre sur loopback. Le port `443` doit être libre si HTTPS sera assuré par Nginx.

## 3. Déployer avec Portainer

### Créer la stack Repository

1. Ouvrir Portainer puis **Stacks** → **Add stack**.
2. Nommer la stack `fortiflow`.
3. Choisir **Repository**.
4. Renseigner :

```text
Repository URL       : https://github.com/Tetrax/FortiFlow
Repository reference : refs/heads/main
Compose path         : docker-compose.portainer.yml
```

5. Cliquer **Deploy the stack**.

> Utiliser exclusivement le mode Repository. Le compose télécharge l’image GHCR ; aucun TAR manuel n’est nécessaire.

### Configuration appliquée

Le compose définit déjà les paramètres nécessaires, dont `PORT=3737`, les limites d’import et les chemins TLS `/certs/privkey.pem` et `/certs/fullchain.pem`. Aucune variable Portainer supplémentaire n’est requise pour le déploiement initial.

## 4. Vérifier le déploiement

### Contrôler le conteneur

Dans Portainer, ouvrir **Containers**. `fortiflow` doit être **running** puis **healthy**.

```bash
docker ps --filter name=fortiflow
docker logs --tail 50 fortiflow
docker inspect --format '{{.State.Health.Status}}' fortiflow
```

Le dernier résultat attendu est `healthy`.

### Tester l’application depuis la VM

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:13737/ >/dev/null
```

Le mapping hôte est volontairement limité à `127.0.0.1`. L’accès utilisateur passe par HTTPS.

## 5. Configurer HTTPS

### Option recommandée : Nginx et PKI interne

Obtenir auprès de la PKI interne un certificat contenant le FQDN dans le SAN, par exemple `fortiflow.monentreprise.lan`, puis copier le certificat et sa clé :

```bash
install -m 644 fortiflow.crt \
  /srv/fortiflow/certificates/fullchain.pem
install -m 600 fortiflow.key \
  /srv/fortiflow/certificates/privkey.pem
```

Installer Nginx si nécessaire, puis créer `/etc/nginx/sites-available/fortiflow` :

```nginx
server {
    listen 443 ssl;
    server_name fortiflow.monentreprise.lan;

    ssl_certificate \
        /srv/fortiflow/certificates/fullchain.pem;
    ssl_certificate_key \
        /srv/fortiflow/certificates/privkey.pem;

    client_max_body_size 2048m;
    proxy_read_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:13737;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For \
            $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

```bash
ln -s /etc/nginx/sites-available/fortiflow \
  /etc/nginx/sites-enabled/fortiflow
nginx -t
systemctl reload nginx
curl --fail --silent --show-error \
  https://fortiflow.monentreprise.lan/ >/dev/null
```

Le poste client doit résoudre le FQDN et faire confiance à la CA interne.

### Variante supportée : TLS direct dans l’application

FortiFlow bascule automatiquement en HTTPS si ces deux fichiers existent :

```text
/etc/ssl/fortiflow/privkey.pem
/etc/ssl/fortiflow/fullchain.pem
```

Après dépôt des fichiers, utiliser **Pull and redeploy** puis vérifier localement avec `curl -k https://127.0.0.1:13737/`. Le compose conservant un binding loopback, un reverse proxy ou une modification explicite du mapping est nécessaire pour un accès réseau direct.

> Ne jamais stocker une clé privée dans Git, l’image ou une variable Portainer.

## 6. Mettre à jour

### Redéployer l’image courante

1. Ouvrir Portainer → **Stacks** → `fortiflow`.
2. Cliquer **Pull and redeploy**.
3. Confirmer avec **Update**.
4. Attendre le retour à l’état **healthy**.

Portainer récupère `ghcr.io/tetrax/fortiflow:latest` et recrée le conteneur. Les volumes persistants restent attachés.

### Vérifier après mise à jour

```bash
docker inspect --format '{{.State.Health.Status}}' fortiflow
docker logs --tail 50 fortiflow
curl --fail --silent --show-error \
  http://127.0.0.1:13737/ >/dev/null
```

Tester ensuite l’URL HTTPS depuis un poste du réseau interne.

## 7. Dépannage

| Symptôme | Vérification ou action |
|---|---|
| Stack non déployée | Vérifier l’URL, `refs/heads/main`, le chemin du compose et l’accès à `ghcr.io`. |
| Conteneur non healthy | Lire `docker logs --tail 100 fortiflow` et contrôler les fichiers TLS. |
| Réponse absente sur 13737 | Vérifier `docker ps` puis `ss -tlnp | grep 13737`. |
| Nginx renvoie 502 | Confirmer que FortiFlow répond en HTTP sur `127.0.0.1:13737`. |
| Alerte certificat | Vérifier DNS, SAN, dates, chaîne et confiance dans la CA interne. |
| TLS direct ne démarre pas | Vérifier les noms, permissions et format PEM des deux fichiers. |
| Image introuvable | Confirmer `ghcr.io/tetrax/fortiflow:latest` et relancer **Pull and redeploy**. |

## 8. Checklist finale

- [ ] Docker et Portainer sont opérationnels.
- [ ] La stack `fortiflow` utilise le mode Repository.
- [ ] Le dépôt, la branche et le chemin du compose sont exacts.
- [ ] L’image GHCR a été téléchargée sans build ni TAR manuel.
- [ ] Le conteneur `fortiflow` est `healthy`.
- [ ] L’application répond sur `127.0.0.1:13737` depuis la VM.
- [ ] Le FQDN interne résout l’adresse de la VM.
- [ ] HTTPS répond avec un certificat approuvé.
- [ ] Le port public est limité aux réseaux autorisés.
- [ ] Les volumes persistants et les clés privées sont préservés.
- [ ] La procédure **Pull and redeploy** → **Update** a été testée.
