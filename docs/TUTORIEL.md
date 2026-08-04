# FortiFlow — Guide opérationnel

> Déploiement initial, HTTPS, mise à jour et dépannage avec Portainer Repository et l’image GHCR.

**Sommaire**

1. Prérequis
2. Préparer le serveur cible
3. Déployer avec Portainer
4. Vérifier le déploiement
5. Configurer HTTPS
6. Mettre à jour
7. Dépannage
8. Checklist finale

## 1. Prérequis

- VM Linux avec Docker Engine 20.10+ et Docker Compose v2.
- Portainer Community Edition, compte administrateur et accès SSH administrateur.
- Accès sortant vers GitHub et `ghcr.io`.
- Adresse IP fixe ; pour HTTPS, FQDN interne, certificat avec ce FQDN dans le SAN et CA approuvée par les clients.
- Règles firewall limitées aux réseaux autorisés.

| Élément | Valeur |
|---|---|
| Dépôt | `https://github.com/Tetrax/FortiFlow` |
| Référence | `refs/heads/main` |
| Compose | `docker-compose.portainer.yml` |
| Image | `ghcr.io/tetrax/fortiflow:latest` |
| Service | `fortiflow` |
| Mapping hôte | `127.0.0.1:13737:3737` |
| Persistance | `fortiflow_sessions`, `fortiflow_workspaces`, `fortiflow_uploads` |

> Utiliser la méthode Repository et l’image GHCR. Ne jamais stocker de clé privée dans Git, l’image ou une variable Portainer.

## 2. Préparer le serveur cible

Vérifier Docker, Portainer et les ports de la première installation :

```bash
docker version
docker ps --filter name=portainer
ss -tlnp | grep -E ':(13737|443)\b' || true
```

Docker et Portainer doivent répondre. `13737` doit être libre ; `443` doit être libre si Nginx sera utilisé.

Préparer les répertoires TLS sans empêcher l’application non-root de traverser son montage :

```bash
mkdir -p /etc/ssl/fortiflow /srv/fortiflow/certificates
chmod 711 /etc/ssl/fortiflow
chmod 700 /srv/fortiflow/certificates
```

Laisser `/etc/ssl/fortiflow` sans paire `privkey.pem` + `fullchain.pem` pour le premier démarrage HTTP. Le mode `711` autorise seulement la traversée ; les droits de la clé restent restrictifs. Les volumes applicatifs sont créés par Docker et ne doivent jamais être supprimés lors d’un redéploiement.

## 3. Déployer avec Portainer

1. Ouvrir **Stacks** → **Add stack**.
2. Nommer la stack `fortiflow`.
3. Choisir **Repository**.
4. Renseigner :

```text
Repository URL       : https://github.com/Tetrax/FortiFlow
Repository reference : refs/heads/main
Compose path         : docker-compose.portainer.yml
```

5. Cliquer **Deploy the stack**.

Portainer tire `ghcr.io/tetrax/fortiflow:latest`, crée `fortiflow` et attache les trois volumes. Aucune variable supplémentaire n’est requise pour le premier démarrage.

## 4. Vérifier le déploiement

```bash
docker ps --filter name=fortiflow
docker logs --tail 50 fortiflow
docker inspect --format '{{.State.Health.Status}}' fortiflow
curl --fail --silent --show-error \
  http://127.0.0.1:13737/ >/dev/null
```

Le conteneur doit être `running (healthy)`, le dernier résultat doit être `healthy` et la requête HTTP locale doit réussir. Dans Portainer, confirmer que les trois volumes sont attachés.

## 5. Configurer HTTPS

Les modes **Nginx** et **TLS direct** sont exclusifs : avec Nginx, laisser `/etc/ssl/fortiflow` sans paire active afin que le backend reste en HTTP.

### Option recommandée : Nginx

Installer le certificat et la clé remis par la PKI :

```bash
install -m 644 /chemin/fullchain.pem \
  /srv/fortiflow/certificates/fullchain.pem
install -m 600 /chemin/privkey.pem \
  /srv/fortiflow/certificates/privkey.pem
```

Créer `/etc/nginx/sites-available/fortiflow` après remplacement du FQDN :

```nginx
server {
    listen 443 ssl;
    server_name fortiflow.monentreprise.lan;

    ssl_certificate /srv/fortiflow/certificates/fullchain.pem;
    ssl_certificate_key /srv/fortiflow/certificates/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 2048m;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

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

```bash
ln -s /etc/nginx/sites-available/fortiflow \
  /etc/nginx/sites-enabled/fortiflow
nginx -t
systemctl reload nginx
curl --fail --silent --show-error \
  https://fortiflow.monentreprise.lan/ >/dev/null
```

`nginx -t` doit réussir. La VM ou le poste de test doit résoudre le FQDN et approuver la CA interne.

### Variante conditionnelle : TLS direct

Cette variante n’est autorisée que si l’administrateur a vérifié le GID utilisé par l’application dans le conteneur. Avec ce GID validé, installer une clé lisible par ce groupe, jamais par tous :

```bash
TLS_GID='<GID_VALIDE>'
chown root:"$TLS_GID" /etc/ssl/fortiflow
chmod 750 /etc/ssl/fortiflow
install -o root -g "$TLS_GID" -m 640 /chemin/privkey.pem \
  /etc/ssl/fortiflow/privkey.pem
install -o root -g "$TLS_GID" -m 644 /chemin/fullchain.pem \
  /etc/ssl/fortiflow/fullchain.pem
```

Si l’identité ou le groupe n’est pas vérifiable, conserver Nginx. Après dépôt des deux fichiers, exécuter **Pull and redeploy** puis **Update**, et contrôler :

```bash
curl --fail --silent --show-error \
  -k https://127.0.0.1:13737/ >/dev/null
```

## 6. Mettre à jour

Le workflow publie `latest` et un tag immuable `ghcr.io/tetrax/fortiflow:<SHA>`. Avant toute mise à jour, relever un `<SHA_PRECEDENT>` connu et sauvegarder les trois volumes à froid.

1. Arrêter `fortiflow` depuis Portainer, puis exécuter :

```bash
BACKUP_DIR="/srv/backups/fortiflow/$(date +%Y%m%d-%H%M%S)"
install -d -m 700 "$BACKUP_DIR"
docker inspect --format \
  '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' \
  fortiflow > "$BACKUP_DIR/volumes.txt"
test "$(wc -l < "$BACKUP_DIR/volumes.txt")" -eq 3

while IFS= read -r VOLUME; do
  docker run --rm \
    --mount type=volume,src="$VOLUME",dst=/source,readonly \
    --mount type=bind,src="$BACKUP_DIR",dst=/backup \
    busybox:1.36.1 sh -eu -c \
    'mkdir -p "/backup/$1"; cp -a /source/. "/backup/$1/"' \
    sh "$VOLUME"
done < "$BACKUP_DIR/volumes.txt"
```

2. Redémarrer `fortiflow`, puis dans Portainer ouvrir la stack, cliquer **Pull and redeploy** et confirmer avec **Update**.
3. Attendre `healthy`, relire les logs, tester le protocole actif et vérifier les volumes.

Pour revenir en arrière, faire valider dans la référence Git utilisée par la stack un compose où `image:` pointe vers `ghcr.io/tetrax/fortiflow:<SHA_PRECEDENT>`, puis refaire **Pull and redeploy** → **Update**. `latest` ne constitue pas un rollback fiable.

Si les données doivent aussi être restaurées, arrêter `fortiflow`, conserver les volumes en échec, puis restaurer la sauvegarde :

```bash
BACKUP_DIR='/srv/backups/fortiflow/<SAUVEGARDE_VALIDEE>'
while IFS= read -r VOLUME; do
  docker run --rm \
    --mount type=volume,src="$VOLUME",dst=/target \
    --mount type=bind,src="$BACKUP_DIR",dst=/backup,readonly \
    busybox:1.36.1 sh -eu -c \
    'find /target -mindepth 1 -maxdepth 1 -exec rm -rf {} +; cp -a "/backup/$1/." /target/' \
    sh "$VOLUME"
done < "$BACKUP_DIR/volumes.txt"
```

Redémarrer ensuite la stack épinglée au SHA précédent et refaire tous les contrôles du chapitre 4. Tester cette restauration hors production avant de l’adopter.

## 7. Dépannage

| Symptôme | Vérification ou action |
|---|---|
| Stack non déployée | Vérifier URL, référence, compose et accès à `ghcr.io`. |
| Conteneur non healthy | Lire `docker logs --tail 100 fortiflow` et vérifier les volumes. |
| Nginx ne recharge pas | Exécuter `nginx -t` et corriger la directive indiquée. |
| Nginx renvoie 502 | Vérifier que le backend répond en HTTP et qu’aucune paire TLS directe n’est active. |
| TLS direct ne démarre pas | Vérifier noms PEM, GID, traversée du répertoire et lecture de la clé par l’utilisateur applicatif. |
| Alerte certificat | Vérifier DNS, SAN, dates, chaîne et confiance dans la CA. |
| Mise à jour défaillante | Épingler le SHA précédent ; restaurer les volumes seulement si nécessaire et depuis une sauvegarde testée. |

## 8. Checklist finale

- [ ] Docker 20.10+ et Portainer sont opérationnels.
- [ ] La stack utilise Repository, la bonne référence et le bon compose.
- [ ] `fortiflow` est `healthy` et les trois volumes sont attachés.
- [ ] Un seul mode HTTPS est actif ; Nginx a passé `nginx -t` ou le TLS direct a un groupe validé.
- [ ] Le FQDN, le SAN, la chaîne, la CA et le firewall sont validés.
- [ ] La clé privée n’est lisible ni par tous ni depuis Git ou Portainer.
- [ ] Une sauvegarde à froid et sa restauration ont été testées.
- [ ] Le SHA précédent est connu et la procédure **Pull and redeploy** → **Update** est validée.
