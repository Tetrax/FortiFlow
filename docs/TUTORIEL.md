# FortiFlow — Guide opérationnel Portainer

> Déploiement initial, import PFX et HTTPS direct avec l’image GHCR. FortiFlow termine TLS lui-même.

## 1. Prérequis

- Docker Engine 20.10+ et Portainer Community Edition.
- Accès au dépôt `https://github.com/Tetrax/FortiFlow` et à `ghcr.io`.
- Un FQDN résolu par les clients et présent dans le SAN du certificat serveur.
- Un bundle PFX fictif pour les essais, puis un PFX délivré par la PKI pour la production.
- Une règle firewall limitant le port publié aux réseaux autorisés.

La stack utilise `docker-compose.portainer.yml`, l’image `ghcr.io/tetrax/fortiflow:latest` et conserve les trois volumes applicatifs : `fortiflow_sessions`, `fortiflow_workspaces` et `fortiflow_uploads`.

> Ne jamais stocker le PFX, la clé privée ou son mot de passe dans Git, l’image, le Compose ou une variable Portainer.

## 2. Préparer l’hôte

Créer le répertoire persistant qui recevra les générations TLS atomiques :

```bash
install -d -m 700 /srv/fortiflow/certificates
```

Dans Portainer, créer une stack par la méthode **Repository** :

```text
Repository URL       : https://github.com/Tetrax/FortiFlow
Repository reference : refs/heads/main
Compose path         : docker-compose.portainer.yml
```

Variables de stack pour le premier démarrage HTTP :

```text
FORTIFLOW_BIND_ADDRESS=127.0.0.1
FORTIFLOW_HTTPS_PORT=13737
FORTIFLOW_CERTIFICATES_PATH=/srv/fortiflow/certificates
FORTIFLOW_TLS_CERT=
FORTIFLOW_TLS_KEY=
FORTIFLOW_TLS_HOSTNAME=
```

Les trois variables TLS doivent être soit toutes vides (HTTP), soit toutes renseignées (HTTPS). Une configuration partielle arrête explicitement le service ; elle ne provoque jamais de fallback HTTP.

Déployer puis vérifier :

```bash
docker ps --filter name=fortiflow
docker inspect --format '{{.State.Health.Status}}' fortiflow
curl --fail http://127.0.0.1:13737/ >/dev/null
```

## 3. Importer un PFX depuis le tmpfs

Le conteneur monte `/tmp` en `tmpfs`. Copier temporairement le PFX, transmettre le mot de passe par fichier de mode `0600`, puis lancer la CLI. Le mot de passe n’apparaît ni dans les arguments de processus ni dans les variables de la stack.

```bash
PFX_SOURCE='/chemin/fortiflow.pfx'
TLS_HOSTNAME='fortiflow.monentreprise.lan'

docker exec -i fortiflow sh -c \
  'umask 077; cat > /tmp/fortiflow-import.pfx' \
  < "$PFX_SOURCE"

IFS= read -rsp 'Mot de passe PFX : ' PFX_PASSWORD
printf '\n'
printf '%s' "$PFX_PASSWORD" | docker exec -i fortiflow \
  sh -c 'umask 077; cat > /tmp/fortiflow-pfx.password'
unset PFX_PASSWORD

docker exec fortiflow fortiflow-certctl install \
  /tmp/fortiflow-import.pfx \
  --password-file /tmp/fortiflow-pfx.password \
  --hostname "$TLS_HOSTNAME" \
  --output-dir /certificates/active

docker exec fortiflow rm -f \
  /tmp/fortiflow-import.pfx /tmp/fortiflow-pfx.password
```

`fortiflow-certctl` valide avant publication : mot de passe, dates, SAN DNS/FQDN, usage serveur et chaîne, ainsi que la correspondance clé/certificat. Il normalise les PEM, applique des modes restrictifs et remplace atomiquement le lien `/certificates/active`. Si une validation échoue, la génération active précédente reste inchangée.

Vérifier la publication sans afficher de donnée privée :

```bash
docker exec fortiflow test -L /certificates/active
docker exec fortiflow openssl x509 \
  -in /certificates/active/fullchain.pem -noout -checkhost "$TLS_HOSTNAME"
docker exec fortiflow stat -Lc \
  'cible=%N mode=%a propriétaire=%u:%g' /certificates/active
docker exec fortiflow stat -Lc \
  'clé=%N mode=%a propriétaire=%u:%g' /certificates/active/privkey.pem
docker exec fortiflow su-exec fortiflow test -r \
  /certificates/active/privkey.pem \
  && echo 'Clé lisible par FortiFlow'
```

La cible active doit être en `0750`, la clé en `0640`, avec le groupe de l’utilisateur `fortiflow`. Le lien `active` est remplacé atomiquement ; ses propres permissions ne déterminent pas l’accès aux fichiers.

## 4. Activer HTTPS direct

Vérifier que le port `443` est libre. Dans les variables Portainer, conserver le chemin hôte, remplacer l'adresse d'écoute par l'IP LAN de la VM et basculer le port hôte vers `443`, puis définir exactement :

```text
FORTIFLOW_BIND_ADDRESS=<IP_LAN_VM>
FORTIFLOW_HTTPS_PORT=443
FORTIFLOW_TLS_CERT=/certificates/active/fullchain.pem
FORTIFLOW_TLS_KEY=/certificates/active/privkey.pem
FORTIFLOW_TLS_HOSTNAME=fortiflow.monentreprise.lan
```

Faire **Pull and redeploy** puis **Update**. Le healthcheck choisit strictement HTTPS lorsque les trois variables sont présentes et HTTP lorsqu’elles sont toutes vides.

```bash
docker logs --tail 50 fortiflow
docker inspect --format '{{.State.Health.Status}}' fortiflow
curl --fail --cacert /chemin/ca.pem \
  --resolve fortiflow.monentreprise.lan:443:<IP_LAN_VM> \
  https://fortiflow.monentreprise.lan/ >/dev/null
```

Ne pas utiliser `-k` pour la validation finale : le client doit approuver la CA et vérifier le FQDN.

## 5. Rotation du certificat

Répéter l’import PFX avec le même `--output-dir`. L’activation est atomique et conserve l’ancien actif en cas d’échec. Après un import réussi, redéployer la stack pour que le processus Node recharge la nouvelle paire, puis refaire les contrôles HTTPS et de santé.

## 6. Mise à jour et rollback

Avant une mise à jour, sauvegarder les trois volumes applicatifs et `/srv/fortiflow/certificates`. Le workflow publie `latest` et un tag immuable `ghcr.io/tetrax/fortiflow:<SHA>`. Pour un rollback fiable, épingler un SHA connu dans le Compose, redéployer, puis vérifier le protocole actif et les volumes.

## 7. Dépannage

| Symptôme | Vérification ou action |
|---|---|
| Échec d’import PFX | Vérifier le mot de passe, les dates, le SAN, la chaîne et la correspondance clé/certificat. L’actif précédent doit rester inchangé. |
| Service arrêté au démarrage | Vérifier que les trois variables `FORTIFLOW_TLS_*` sont toutes vides ou toutes définies. |
| Fichier TLS introuvable | Vérifier `FORTIFLOW_CERTIFICATES_PATH` et le lien persistant `certificates/active`. |
| Conteneur `unhealthy` | Lire les logs et tester le même protocole que celui déterminé par les variables TLS. |
| Alerte navigateur | Vérifier DNS, SAN, dates, chaîne complète et confiance dans la CA. |
| Port inaccessible | Vérifier `FORTIFLOW_BIND_ADDRESS`, `FORTIFLOW_HTTPS_PORT` et le firewall hôte. |

## 8. Checklist finale

- [ ] Les trois volumes applicatifs et le répertoire de certificats sont persistants.
- [ ] `/tmp` est un tmpfs et les fichiers d’import ont été supprimés.
- [ ] Aucun mot de passe ou matériel privé n’est dans Git, Compose ou Portainer.
- [ ] Les trois variables TLS sont cohérentes et le service ne fait aucun fallback silencieux.
- [ ] Le healthcheck est `healthy` dans le protocole configuré.
- [ ] Le FQDN, le SAN, la chaîne, la CA, le port et le firewall sont validés.
- [ ] La rotation et le rollback ont été testés avec des PFX fictifs avant la production.
