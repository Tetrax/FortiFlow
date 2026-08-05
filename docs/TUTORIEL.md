# FortiFlow — Tutoriel d’installation et de mise à jour

> Portainer Repository, image GHCR, certificat PFX et HTTPS direct. Aucun Nginx, aucun reverse proxy, aucun secret dans Git ou dans les variables de stack.

## 1. Choisir le bon parcours

### Cas A — La stack `fortiflow` existe déjà dans Portainer

Si elle contient déjà les trois valeurs suivantes, **ne la recrée pas** :

```text
Repository URL       : https://github.com/Tetrax/FortiFlow
Repository reference : refs/heads/main
Compose path         : docker-compose.portainer.yml
```

La mise à niveau se fait depuis **Stacks → fortiflow → Pull and redeploy → Update**.

Pour la première activation PFX, le parcours comporte volontairement deux mises à jour :

1. mettre à jour avec TLS vide pour récupérer l’image contenant `fortiflow-certctl` ;
2. importer le PFX, renseigner les variables TLS, puis refaire **Pull and redeploy → Update** pour démarrer en HTTPS.

> Si la stack utilise déjà l’image PFX et que `/certificates/active` existe, les mises à jour applicatives suivantes ne demandent qu’un seul **Pull and redeploy → Update**.

### Cas B — La stack n’existe pas

Créer une stack Portainer de type **Repository** avec les trois valeurs ci-dessus. Ne pas utiliser Web editor, TAR, build manuel ou import d’image local.

### Architecture finale

```text
Client HTTPS
    |
    | https://<FQDN>:443
    v
IP LAN de la VM:443
    |
    | publication Docker
    v
FortiFlow:3737 — TLS terminé directement par Node.js
```

L’image est `ghcr.io/tetrax/fortiflow:latest`. Les trois volumes applicatifs et le répertoire de certificats survivent aux recréations du conteneur.

## 2. Préparer la VM et Portainer

### Prérequis

- Docker Engine et Portainer opérationnels ;
- accès de la VM à GitHub et à `ghcr.io` ;
- FQDN résolu vers l’IP LAN réellement utilisée ;
- certificat PFX dont le SAN contient exactement ce FQDN ;
- accès SSH root à la VM pour l’import initial ;
- port `443` autorisé uniquement depuis les réseaux nécessaires.

Ne jamais placer le PFX, sa clé privée ou son mot de passe dans Git, le Compose, une variable Portainer, Discord ou un rapport.

### Vérifier Docker et le port 443

Exécuter séparément :

```bash
docker ps
```

Puis contrôler le port sans interrompre le shell :

```bash
if ss -ltnp | grep -qE '(^|[[:space:]])[^[:space:]]*:443[[:space:]]'; then
  echo 'Port 443 déjà occupé : identifier le service avant de continuer'
else
  echo 'Port 443 libre'
fi
```

Ne pas poursuivre si un autre service écoute déjà sur l’adresse choisie et le port `443`.

### Préparer le stockage persistant TLS

```bash
install -d -m 700 /srv/fortiflow/certificates
stat -c 'mode=%a propriétaire=%U:%G chemin=%n' \
  /srv/fortiflow/certificates
```

### Variables Portainer pour le bootstrap HTTP local

Dans **Stacks → fortiflow → Environment variables**, définir :

```text
FORTIFLOW_BIND_ADDRESS=127.0.0.1
FORTIFLOW_HTTPS_PORT=13737
FORTIFLOW_CERTIFICATES_PATH=/srv/fortiflow/certificates
FORTIFLOW_TLS_CERT=
FORTIFLOW_TLS_KEY=
FORTIFLOW_TLS_HOSTNAME=
```

Les trois variables TLS doivent être soit toutes vides, soit toutes renseignées. Une configuration partielle arrête FortiFlow ; aucun fallback HTTP silencieux n’est autorisé.

Les autres paramètres applicatifs peuvent conserver leurs valeurs par défaut. Ne pas ajouter de variable contenant le mot de passe du PFX.

## 3. Mettre à niveau ou installer la stack

### Stack existante déjà liée à GitHub

1. Ouvrir **Portainer → Stacks → fortiflow**.
2. Vérifier la branche `refs/heads/main` et le chemin `docker-compose.portainer.yml`.
3. Vérifier les six variables du bootstrap HTTP.
4. Cliquer **Pull and redeploy**.
5. Confirmer avec **Update**.
6. Attendre que le conteneur `fortiflow` soit `healthy`.

Tu n’as pas à supprimer ni recréer la stack. Portainer récupère le Compose depuis GitHub et l’image `latest` depuis GHCR. Les volumes existants restent attachés.

### Nouvelle stack Repository

1. Ouvrir **Stacks → Add stack → Repository**.
2. Nommer la stack `fortiflow`.
3. Saisir le dépôt, la référence et le chemin Compose indiqués au chapitre 1.
4. Ajouter les six variables du bootstrap HTTP.
5. Déployer la stack.
6. Attendre l’état `healthy`.

### Contrôles du bootstrap

```bash
docker ps --filter name=fortiflow
docker inspect --format '{{.State.Health.Status}}' fortiflow
curl --fail http://127.0.0.1:13737/ >/dev/null \
  && echo 'Bootstrap HTTP local opérationnel'
docker exec fortiflow command -v fortiflow-certctl
```

Le dernier contrôle doit retourner `/usr/local/bin/fortiflow-certctl`. Si la commande est absente, l’ancienne image est encore utilisée : refaire **Pull and redeploy → Update** et attendre la fin du pull.

## 4. Importer et valider le certificat PFX

### Préparer les valeurs non secrètes

Le PFX doit être présent temporairement sur la VM, hors du dépôt Git :

```bash
PFX_SOURCE='/chemin/protege/fortiflow.pfx'
TLS_HOSTNAME='fortiflow.monentreprise.lan'

test -f "$PFX_SOURCE" \
  && echo 'PFX source présent' \
  || echo 'PFX source introuvable : corriger le chemin'
```

Remplacer les exemples par le chemin réel et le véritable FQDN. Ne jamais inventer le FQDN : il doit être couvert par le SAN du certificat.

### Injecter le PFX et le mot de passe dans le tmpfs

Le PFX et le fichier de mot de passe sont écrits uniquement dans `/tmp` du conteneur, monté en `tmpfs`. Le mot de passe n’apparaît ni dans la ligne de commande du processus ni dans les variables Portainer.

```bash
docker exec -i fortiflow sh -c \
  'umask 077; cat > /tmp/fortiflow-import.pfx' \
  < "$PFX_SOURCE"

IFS= read -rsp 'Mot de passe PFX : ' PFX_PASSWORD
printf '\n'
printf '%s' "$PFX_PASSWORD" | docker exec -i fortiflow \
  sh -c 'umask 077; cat > /tmp/fortiflow-pfx.password'
unset PFX_PASSWORD
```

### Installer le certificat

```bash
docker exec fortiflow fortiflow-certctl install \
  /tmp/fortiflow-import.pfx \
  --password-file /tmp/fortiflow-pfx.password \
  --hostname "$TLS_HOSTNAME" \
  --output-dir /certificates/active
CERTCTL_RC=$?

docker exec fortiflow rm -f \
  /tmp/fortiflow-import.pfx /tmp/fortiflow-pfx.password

printf 'Code retour certctl : %s\n' "$CERTCTL_RC"
```

Un code retour `0` confirme l’installation. Si le code est différent, ne pas activer HTTPS : corriger le PFX, le mot de passe, la chaîne ou le FQDN, puis recommencer.

`fortiflow-certctl` contrôle avant publication :

- le mot de passe PKCS#12 ;
- les dates de validité ;
- la présence d’un SAN DNS et sa correspondance avec le FQDN ;
- l’usage serveur ;
- la chaîne de certificats ;
- la correspondance entre clé privée et certificat.

La publication est atomique. Un import invalide ne remplace pas la génération active précédente.

### Vérifier sans afficher la clé

```bash
docker exec fortiflow test -L /certificates/active \
  && echo 'Génération active présente'

docker exec fortiflow openssl x509 \
  -in /certificates/active/fullchain.pem \
  -noout -subject -issuer -dates -checkhost "$TLS_HOSTNAME"

docker exec fortiflow stat -Lc \
  'cible=%N mode=%a propriétaire=%u:%g' /certificates/active

docker exec fortiflow stat -Lc \
  'clé=%N mode=%a propriétaire=%u:%g' \
  /certificates/active/privkey.pem

docker exec fortiflow su-exec fortiflow test -r \
  /certificates/active/privkey.pem \
  && echo 'Clé lisible par FortiFlow'
```

La cible active doit être en `0750` et la clé en `0640`, avec le groupe de l’utilisateur `fortiflow`.

Après validation, supprimer également la copie PFX temporaire conservée sur la VM si la politique PKI n’impose pas son archivage. Si elle doit être conservée, la déplacer vers un stockage chiffré et contrôlé.

## 5. Activer et vérifier HTTPS direct

### Modifier les variables Portainer

Dans la même stack, remplacer uniquement les valeurs nécessaires :

```text
FORTIFLOW_BIND_ADDRESS=<IP_LAN_VM>
FORTIFLOW_HTTPS_PORT=443
FORTIFLOW_CERTIFICATES_PATH=/srv/fortiflow/certificates
FORTIFLOW_TLS_CERT=/certificates/active/fullchain.pem
FORTIFLOW_TLS_KEY=/certificates/active/privkey.pem
FORTIFLOW_TLS_HOSTNAME=<FQDN_REEL>
```

Utiliser l’adresse LAN précise de la VM pour limiter l’exposition. N’utiliser `0.0.0.0` que si l’écoute sur toutes les interfaces est réellement voulue et filtrée par le firewall.

### Redéployer

1. Ouvrir **Stacks → fortiflow**.
2. Cliquer **Pull and redeploy**.
3. Cliquer **Update**.
4. Attendre le retour à `healthy`.

Docker publie alors :

```text
<IP_LAN_VM>:443 → fortiflow:3737
```

Le processus Node.js continue d’écouter sur le port non privilégié `3737` dans le conteneur et termine lui-même TLS.

### Vérifier le conteneur

```bash
docker inspect --format '{{.State.Health.Status}}' fortiflow
docker logs --tail 80 fortiflow
```

Le journal doit annoncer HTTPS, le port interne `3737` et le FQDN configuré. Une configuration TLS partielle ou un fichier illisible doit provoquer un échec explicite.

### Vérifier depuis un client

Avec une CA interne :

```bash
curl --fail --cacert /chemin/ca.pem \
  --resolve <FQDN_REEL>:443:<IP_LAN_VM> \
  https://<FQDN_REEL>/ >/dev/null \
  && echo 'HTTPS FortiFlow validé'
```

Avec une CA déjà approuvée par le système :

```bash
curl --fail https://<FQDN_REEL>/ >/dev/null \
  && echo 'HTTPS FortiFlow validé'
```

Ne pas utiliser `curl -k` pour la validation finale. Vérifier également depuis un navigateur autorisé : cadenas valide, FQDN correct et absence d’alerte de chaîne.

## 6. Mettre à jour FortiFlow ou renouveler le PFX

### Mise à jour applicative courante

Quand la stack est déjà configurée en HTTPS et que le certificat actif est valide :

1. ouvrir **Stacks → fortiflow** ;
2. vérifier que les six variables sont toujours présentes ;
3. cliquer **Pull and redeploy** ;
4. confirmer avec **Update** ;
5. attendre `healthy` ;
6. refaire le test HTTPS.

Aucun nouvel import PFX n’est nécessaire pour une simple mise à jour applicative. Les trois volumes et `/srv/fortiflow/certificates` sont conservés.

### Vérifications après chaque mise à jour

```bash
docker inspect --format '{{.State.Health.Status}}' fortiflow
docker logs --tail 50 fortiflow
curl --fail https://<FQDN_REEL>/ >/dev/null \
  && echo 'Mise à jour validée'
```

Si la CA est interne, conserver l’option `--cacert /chemin/ca.pem`.

### Renouvellement du certificat

1. conserver les variables TLS actuelles ;
2. importer le nouveau PFX avec la procédure du chapitre 4 ;
3. vérifier SAN, dates et permissions ;
4. faire **Pull and redeploy → Update** pour redémarrer Node.js ;
5. vérifier le nouveau certificat depuis un client.

Le lien `active` est remplacé atomiquement. Si le nouveau PFX échoue, l’ancien certificat actif reste intact et la stack ne doit pas être redéployée.

## 7. Sauvegarde, rollback et dépannage

### Identifier les stockages persistants

```bash
docker inspect fortiflow --format \
  '{{range .Mounts}}{{println .Destination "<-" .Name .Source}}{{end}}'
```

Avant une mise à jour importante, sauvegarder :

- le volume monté sur `/sessions-cache` ;
- le volume monté sur `/app/workspaces` ;
- le volume monté sur `/app/uploads` ;
- `/srv/fortiflow/certificates` vers un stockage protégé.

Le répertoire TLS contient une clé privée : sa sauvegarde doit rester chiffrée, avec un accès restreint. Ne jamais l’attacher à un ticket ou à un message.

### Règles de rollback

- ne jamais supprimer les volumes lors d’un rollback ;
- ne pas supprimer `/srv/fortiflow/certificates` ;
- ne pas utiliser `docker system prune -a --volumes` ;
- utiliser un tag GHCR immuable correspondant à un commit connu pour revenir à une version précise ;
- après rollback, vérifier `healthy`, les volumes et HTTPS.

L’image publiée possède `latest` et un tag immuable :

```text
ghcr.io/tetrax/fortiflow:<SHA_GIT>
```

Pour un rollback durable avec une stack Repository, faire modifier dans Git la ligne `image:` du Compose vers le SHA validé, puis utiliser **Pull and redeploy → Update**. Ne pas improviser une suppression manuelle de conteneur ou de volume.

### Dépannage

| Symptôme | Vérification et action |
|---|---|
| `fortiflow-certctl` absent | L’ancienne image tourne encore. Faire Pull and redeploy, attendre le pull et revérifier. |
| Import PFX refusé | Vérifier mot de passe, dates, SAN, usage serveur, chaîne et correspondance clé/certificat. |
| Service arrêté au démarrage | Les trois variables `FORTIFLOW_TLS_*` doivent être toutes vides ou toutes renseignées. |
| Clé illisible | Contrôler le montage `/certificates`, la cible `active`, le mode `0640` et le groupe `fortiflow`. |
| Conteneur `unhealthy` | Lire les logs et vérifier le protocole déterminé par les variables TLS. Le healthcheck contrôle aussi le SAN. |
| Port 443 inaccessible | Vérifier l’IP de bind, le firewall, `ss -ltnp` et le mapping `443:3737`. |
| Alerte navigateur | Vérifier FQDN, SAN, dates, chaîne complète et confiance dans la CA. |
| Données absentes après update | Vérifier que les trois volumes existants sont toujours attachés et qu’ils n’ont pas été recréés ou supprimés. |
| Échec juste après Update | Ne pas supprimer les volumes. Lire les logs, corriger les variables ou revenir à un tag immuable. |

## 8. Checklist finale

### Installation ou première migration PFX

- [ ] La stack pointe vers `https://github.com/Tetrax/FortiFlow`, `refs/heads/main` et `docker-compose.portainer.yml` ; l’image GHCR est accessible.
- [ ] Le port `443` est libre sur l’adresse choisie ; `/srv/fortiflow/certificates` existe en `0700`.
- [ ] Les trois volumes applicatifs sont persistants ; le bootstrap HTTP local est `healthy` et expose `fortiflow-certctl`.
- [ ] Le PFX a été validé avec le véritable FQDN ; les fichiers PFX et mot de passe temporaires ont été supprimés du tmpfs.
- [ ] Aucune donnée secrète n’est dans Git, Compose ou Portainer ; les trois variables TLS sont toutes renseignées.
- [ ] Le mapping final est `<IP_LAN_VM>:443 → 3737` et le conteneur est `healthy` en HTTPS.
- [ ] Le test client valide la CA, la chaîne et le SAN sans `-k`.

### Mise à jour courante

- [ ] Les données et certificats nécessaires sont sauvegardés ; les variables de stack sont conservées.
- [ ] **Pull and redeploy → Update** a été utilisé sans recréer la stack.
- [ ] Les volumes existants sont restés attachés et le conteneur est revenu à `healthy`.
- [ ] Le test HTTPS et le navigateur sont conformes.
- [ ] Aucun prune global ni suppression de volume n’a été effectué.
