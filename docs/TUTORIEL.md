# FortiFlow — Tutoriel de déploiement complet

> Pars d’une VM prête à recevoir Docker. Termine avec FortiFlow `healthy`, accessible en HTTPS direct sur `<IP_VM>:443`, puis utilise la partie finale uniquement pour les mises à jour.

## PARTIE I — INSTALLATION FROM SCRATCH

Cette partie est un parcours unique. Suis les étapes dans l’ordre. Tu vas créer la stack depuis le dépôt GitHub, démarrer FortiFlow en HTTP local, importer le PFX sans exposer son mot de passe, puis basculer en HTTPS.

### 1. Comprendre l’architecture finale

Le déploiement utilise exclusivement ces sources :

| Élément | Valeur |
|---|---|
| Dépôt | `https://github.com/Tetrax/FortiFlow` |
| Référence Git | `refs/heads/main` |
| Compose | `docker-compose.portainer.yml` |
| Image | `ghcr.io/tetrax/fortiflow:latest` |
| Port interne | `3737` — immuable |
| Port hôte final | `443` |
| Certificats persistants | `/srv/fortiflow/certificates` |

```text
Navigateur ou client HTTPS
        |
        | https://<FQDN_REEL>:443
        v
<IP_VM>:443
        |
        | publication Docker
        v
FortiFlow:3737 — terminaison TLS dans l’application
```

Les données applicatives résident dans trois volumes Docker : `/sessions-cache`, `/app/workspaces` et `/app/uploads`. Les certificats résident sur la VM et sont montés dans le conteneur sous `/certificates`.

> **Résultat attendu —** Tu sais que `443` est le port public et que `3737` reste le port interne. Tu n’as rien à compiler ni à importer manuellement dans Portainer.

### 2. Réunir les prérequis

Prépare les éléments suivants avant d’ouvrir Portainer :

- une VM Linux avec un accès shell `root` ;
- Docker Engine et Portainer opérationnels ;
- un accès réseau sortant vers GitHub et `ghcr.io` ;
- une vraie adresse `<IP_VM>` fixe ou réservée ;
- un vrai `<FQDN_REEL>` résolu vers cette adresse ;
- un PFX dont le SAN DNS contient exactement ce FQDN ;
- la chaîne de confiance nécessaire sur les postes clients ;
- un flux entrant TCP `443` limité aux réseaux autorisés.

Les chaînes entre chevrons sont des placeholders. Remplace-les par tes vraies valeurs. N’invente jamais une IP ou un FQDN.

> **Ne continue pas si —** Le PFX ne correspond pas au FQDN, la VM ne joint pas le dépôt ou le registre, ou tu ne disposes pas d’un accès `root`.

### 3. Préparer la VM

#### 3.1 Vérifier Docker et Portainer

Exécute les commandes séparément :

```bash
docker version
docker ps
docker info --format 'Docker {{.ServerVersion}} opérationnel'
```

Dans un navigateur, ouvre l’URL habituelle de Portainer. Vérifie que l’environnement Docker cible est joignable.

> **Résultat attendu —** Les commandes répondent sans erreur et Portainer affiche l’environnement comme actif.

#### 3.2 Vérifier que le port 443 est libre

```bash
if ss -ltnp | grep -qE '(^|[[:space:]])[^[:space:]]*:443[[:space:]]'; then
  echo 'Port 443 occupé : identifier le service avant de continuer'
else
  echo 'Port 443 libre'
fi
```

> **Ne continue pas si —** Un autre service écoute sur `<IP_VM>:443`. Identifie-le et libère le port sans supprimer un service utile.

#### 3.3 Créer le stockage persistant des certificats

```bash
install -d -m 700 /srv/fortiflow/certificates
stat -c 'mode=%a propriétaire=%U:%G chemin=%n' \
  /srv/fortiflow/certificates
```

Le résultat doit indiquer le mode `700`, le propriétaire `root:root` et le bon chemin.

### 4. Créer la stack Repository dans Portainer

#### 4.1 Ouvrir l’assistant

1. Dans la barre latérale, clique **Stacks**.
2. Clique **Add stack**.
3. Dans **Build method**, sélectionne **Repository**.
4. Dans **Name**, saisis `fortiflow`.

> **À faire —** Reste dans le mode Repository. Le Compose doit toujours venir du dépôt officiel.

#### 4.2 Renseigner le dépôt

Dans **Git repository**, saisis exactement :

```text
Repository URL       : https://github.com/Tetrax/FortiFlow
Repository reference : refs/heads/main
Compose path         : docker-compose.portainer.yml
```

Le dépôt est public. Ne renseigne aucun identifiant Git si Portainer n’en demande pas.

> **Résultat attendu —** L’écran affiche le dépôt, la branche `main` sous sa référence complète et le fichier Compose à la racine.

#### 4.3 Laisser les variables vides

Descends jusqu’à **Environment variables**. Pour le premier déploiement, **n’ajoute aucune variable**. Les valeurs de bootstrap sont déjà définies comme valeurs par défaut dans `docker-compose.portainer.yml`.

> **Ne continue pas si —** Le nom de stack, l’URL, la référence ou le chemin Compose diffèrent du tableau ci-dessus.

### 5. Utiliser le bootstrap HTTP par défaut

Le premier démarrage reste volontairement local. Il permet d’obtenir le conteneur et l’outil `fortiflow-certctl` avant d’activer TLS.

Tu n’as rien à saisir dans Portainer à cette étape. Lorsque la section **Environment variables** est vide, le Compose applique automatiquement :

- une écoute hôte locale sur `127.0.0.1` ;
- le port hôte temporaire `13737` vers le port interne `3737` ;
- le stockage des certificats sous `/srv/fortiflow/certificates` ;
- TLS désactivé pour ce premier démarrage.

Ne recopie aucune ligne de configuration et n’ajoute pas le mot de passe du PFX. Ne place jamais le PFX, sa clé privée ou son mot de passe dans Git, le Compose ou Portainer.

Les variables TLS seront ajoutées plus tard, uniquement à l’étape 8 après l’import du PFX. Elles devront alors être toutes renseignées ; une configuration partielle arrête le service.

> **Résultat attendu —** La section Environment variables est vide. Le Compose publiera automatiquement `127.0.0.1:13737` et démarrera FortiFlow en HTTP local.

### 6. Effectuer le premier déploiement

1. En bas de l’écran, clique **Deploy the stack**.
2. Attends le téléchargement du Compose et de l’image GHCR.
3. Ouvre **Containers → fortiflow**.
4. Attends que l’état de santé devienne `healthy`.

Vérifie ensuite depuis le shell `root` de la VM :

```bash
docker ps --filter name=fortiflow
docker inspect --format '{{.State.Health.Status}}' fortiflow
curl --fail http://127.0.0.1:13737/ >/dev/null \
  && echo 'Bootstrap HTTP local opérationnel'
docker exec fortiflow command -v fortiflow-certctl
```

La dernière commande doit afficher `/usr/local/bin/fortiflow-certctl`.

> **Résultat attendu —** Le conteneur est `healthy`, le test HTTP local réussit et `fortiflow-certctl` existe.

> **Ne continue pas si —** Le healthcheck n’est pas `healthy`, le port local ne répond pas ou l’outil est absent. Consulte `docker logs --tail 100 fortiflow` et corrige le premier déploiement.

### 7. Importer le PFX en sécurité

#### 7.1 Définir les vraies valeurs

Place temporairement le PFX sur la VM dans un emplacement protégé, hors du dépôt. Puis adapte ces deux valeurs :

```bash
PFX_SOURCE='<CHEMIN_PFX_REEL>'
TLS_HOSTNAME='<FQDN_REEL>'

test -f "$PFX_SOURCE" \
  && echo 'PFX source présent' \
  || echo 'PFX source introuvable : corriger le chemin'
```

> **Ne continue pas si —** Le test ne confirme pas la présence du PFX ou `TLS_HOSTNAME` n’est pas le nom couvert par son SAN DNS.

#### 7.2 Copier le PFX dans le tmpfs du conteneur

Le `/tmp` du conteneur est un `tmpfs`. Le PFX et son mot de passe y restent temporaires.

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

Le mot de passe n’apparaît ni dans la ligne de commande du processus ni dans la configuration Portainer.

#### 7.3 Installer avec fortiflow-certctl

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

Un code `0` confirme l’installation. L’outil vérifie le mot de passe, les dates, le SAN DNS, le FQDN, l’usage serveur, la chaîne et la correspondance entre certificat et clé. La publication est atomique : un PFX invalide ne remplace pas un certificat actif.

> **Ne continue pas si —** Le code diffère de `0`. Corrige le PFX, son mot de passe, sa chaîne ou le FQDN, puis recommence l’import.

#### 7.4 Vérifier les fichiers sans afficher la clé

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

La cible active doit être en `0750`. La clé doit être en `0640`, avec le groupe du compte `fortiflow`.

> **Résultat attendu —** Le lien `active` existe, le FQDN correspond, les dates sont valides et l’application peut lire la clé.

### 8. Activer HTTPS sur IP_VM:443

#### 8.1 Ajouter les variables HTTPS

Dans **Stacks → fortiflow**, ouvre l’éditeur de la stack. Dans **Environment variables**, ajoute maintenant les six variables suivantes :

```text
FORTIFLOW_BIND_ADDRESS=<IP_VM>
FORTIFLOW_HTTPS_PORT=443
FORTIFLOW_CERTIFICATES_PATH=/srv/fortiflow/certificates
FORTIFLOW_TLS_CERT=/certificates/active/fullchain.pem
FORTIFLOW_TLS_KEY=/certificates/active/privkey.pem
FORTIFLOW_TLS_HOSTNAME=<FQDN_REEL>
```

Utilise l’adresse exacte de la VM. N’emploie `0.0.0.0` que si l’écoute sur toutes les interfaces est voulue et filtrée.

#### 8.2 Appliquer la configuration finale

1. Clique **Pull and redeploy**.
2. Vérifie que l’option de récupération de l’image est active si Portainer la propose.
3. Confirme avec **Update**.
4. Attends que `fortiflow` redevienne `healthy`.

Cette action termine l’installation initiale. Docker publie désormais :

```text
<IP_VM>:443 -> fortiflow:3737
```

Le port interne `3737` ne change jamais. FortiFlow termine lui-même TLS.

> **Ne continue pas si —** Portainer signale une erreur, le conteneur redémarre en boucle ou le healthcheck reste `unhealthy`.

### 9. Valider l’installation finale

#### 9.1 Contrôler le conteneur et le mapping

```bash
docker inspect --format '{{.State.Health.Status}}' fortiflow
docker port fortiflow 3737
docker logs --tail 80 fortiflow
```

Le healthcheck doit répondre `healthy`. Le mapping doit associer `<IP_VM>:443` au port `3737/tcp`. Les journaux doivent annoncer HTTPS sans erreur de certificat.

#### 9.2 Tester le certificat depuis un client

Si la CA est interne :

```bash
curl --fail --cacert <CHEMIN_CA_REEL> \
  --resolve <FQDN_REEL>:443:<IP_VM> \
  https://<FQDN_REEL>/ >/dev/null \
  && echo 'HTTPS FortiFlow validé'
```

Si la CA est déjà approuvée par le système :

```bash
curl --fail https://<FQDN_REEL>/ >/dev/null \
  && echo 'HTTPS FortiFlow validé'
```

N’ignore pas les contrôles TLS. Ouvre aussi `https://<FQDN_REEL>/` dans un navigateur autorisé. Vérifie le cadenas, le nom, la chaîne et les dates.

> **Résultat attendu —** Le client valide TLS, la page FortiFlow s’ouvre et aucune alerte de certificat n’apparaît.

### 10. Réaliser la sauvegarde initiale

Identifie d’abord les montages réels :

```bash
docker inspect fortiflow --format \
  '{{range .Mounts}}{{println .Destination "<-" .Name .Source}}{{end}}'
```

Sauvegarde ensuite, avec ton outil de sauvegarde habituel :

- le volume monté sur `/sessions-cache` ;
- le volume monté sur `/app/workspaces` ;
- le volume monté sur `/app/uploads` ;
- `/srv/fortiflow/certificates` vers un stockage chiffré et restreint.

Teste la restauration sur un emplacement isolé. Le répertoire de certificats contient une clé privée : ne le joins jamais à un ticket, un message ou un dépôt.

> **À faire —** Note les noms de volumes retournés par Docker, la date de la sauvegarde, sa destination et le résultat du test de restauration.

### 11. Checklist de fin d’installation

- [ ] La stack `fortiflow` est une stack Repository reliée au dépôt, à `refs/heads/main` et au bon Compose.
- [ ] L’image exécutée provient de `ghcr.io/tetrax/fortiflow:latest`.
- [ ] Les trois volumes applicatifs sont présents et montés aux bonnes destinations.
- [ ] `/srv/fortiflow/certificates` persiste sur la VM.
- [ ] Aucun PFX, clé privée ou mot de passe n’est dans Git, le Compose ou Portainer.
- [ ] Le PFX a été installé par `fortiflow-certctl install` avec le vrai FQDN.
- [ ] Les fichiers temporaires du conteneur ont été supprimés.
- [ ] Le mapping final est `<IP_VM>:443 -> 3737`.
- [ ] Le conteneur est `healthy` et les journaux ne montrent aucune erreur TLS.
- [ ] Le test HTTPS valide la CA, le SAN, le FQDN et la chaîne.
- [ ] La sauvegarde initiale et son test de restauration sont documentés.

> **Installation terminée —** Ne passe à la partie II que lorsque chaque point applicable est validé.

## PARTIE II — MISE À JOUR

Cette partie s’applique à une installation déjà terminée. Elle ne sert pas à créer une nouvelle stack.

### 12. Effectuer une mise à jour normale

Si le lien GitHub est déjà configuré, **ne recrée pas la stack**. Une mise à jour normale se limite au parcours suivant :

1. Ouvre **Stacks → fortiflow**.
2. Vérifie `https://github.com/Tetrax/FortiFlow`, `refs/heads/main` et `docker-compose.portainer.yml`.
3. Vérifie que les six variables HTTPS sont toujours présentes.
4. Clique **Pull and redeploy**.
5. Confirme avec **Update**.
6. Attends le retour à `healthy`.

Portainer récupère le Compose depuis GitHub et l’image `latest` depuis GHCR. Les volumes et `/srv/fortiflow/certificates` restent attachés. Un nouvel import PFX n’est pas nécessaire pour une mise à jour applicative ordinaire.

> **Résultat attendu —** La stack existante est redéployée sans être supprimée ni recréée.

### 13. Effectuer les contrôles post-MAJ

```bash
docker inspect --format '{{.State.Health.Status}}' fortiflow
docker port fortiflow 3737
docker logs --tail 80 fortiflow
curl --fail https://<FQDN_REEL>/ >/dev/null \
  && echo 'Mise à jour validée'
```

Avec une CA interne, ajoute `--cacert <CHEMIN_CA_REEL>` au test HTTPS.

Contrôle également dans Portainer que les trois volumes d’origine sont toujours montés et que `/certificates` pointe vers `/srv/fortiflow/certificates`.

> **Ne continue pas si —** Le conteneur n’est pas `healthy`, le mapping n’est plus `<IP_VM>:443 -> 3737`, HTTPS échoue ou un volume attendu manque.

### 14. Renouveler le PFX

Le renouvellement du certificat est indépendant d’une mise à jour applicative :

1. Conserve les six variables HTTPS actuelles.
2. Reprends les étapes 7.1 à 7.4 avec le nouveau PFX et le même vrai FQDN.
3. Ne redéploie pas si `fortiflow-certctl install` retourne un code différent de `0`.
4. Si l’import réussit, ouvre **Stacks → fortiflow**.
5. Clique **Pull and redeploy**, puis **Update**, pour redémarrer l’application sur le nouveau certificat.
6. Reprends les validations HTTPS de l’étape 9.

Le lien `active` est remplacé atomiquement. Un PFX invalide laisse l’ancienne génération active intacte.

### 15. Première migration d’une ancienne stack vers le support PFX

Ce cas est exceptionnel. Il concerne une stack Repository déjà reliée à GitHub, mais dont l’image en cours ne contient pas encore `fortiflow-certctl`. Ne le confonds pas avec la mise à jour normale de l’étape 12.

#### 15.1 Ne pas recréer la stack

Conserve la stack existante, ses volumes et son lien GitHub. Vérifie la présence de l’outil :

```bash
docker exec fortiflow command -v fortiflow-certctl
```

Si la commande retourne `/usr/local/bin/fortiflow-certctl`, passe directement à l’import PFX. Sinon, effectue le bootstrap ci-dessous.

#### 15.2 Bootstrap nécessaire une seule fois

1. Dans **Stacks → fortiflow → Environment variables**, retire temporairement les variables `FORTIFLOW_*` de l’ancienne configuration. Ne saisis aucune valeur de bootstrap : les défauts de l’étape 5 sont fournis par le Compose.
2. Clique **Pull and redeploy → Update** pour récupérer l’image qui contient `fortiflow-certctl`.
3. Attends `healthy` et rejoue la commande de vérification ci-dessus.
4. Importe le PFX avec toute l’étape 7.
5. Renseigne les six valeurs HTTPS de l’étape 8.1.
6. Clique une seconde fois **Pull and redeploy → Update**.
7. Exécute toutes les validations de l’étape 9.

Après cette première migration, les mises à jour suivantes reviennent au flux normal de l’étape 12 : un seul **Pull and redeploy → Update**, sans nouvel import PFX.

> **Ne continue pas si —** L’outil reste absent après le premier redéploiement. Vérifie le pull de `ghcr.io/tetrax/fortiflow:latest` et les journaux avant d’importer un certificat.

### 16. Préparer un rollback

Avant une mise à jour importante :

- vérifie la dernière sauvegarde des trois volumes et des certificats ;
- relève le SHA Git complet de la version applicative actuellement validée ;
- confirme que l’image immuable `ghcr.io/tetrax/fortiflow:<SHA_GIT>` existe ;
- documente la version cible et la procédure de retour.

Pour revenir durablement à une version précise avec une stack Repository, fais valider par le mainteneur une révision du Compose qui fixe l’image au tag SHA connu, puis applique **Pull and redeploy → Update**. Ne supprime jamais les volumes ni `/srv/fortiflow/certificates` pendant le rollback.

Après le retour arrière, répète les contrôles de l’étape 13 et vérifie les données fonctionnelles.

> **À faire —** Si tu n’as pas de tag SHA vérifié et de sauvegarde restaurable, n’engage pas un rollback improvisé.

### 17. Dépanner sans détruire les données

| Symptôme | Vérification et action |
|---|---|
| `fortiflow-certctl` absent | Appliquer uniquement le bootstrap de l’étape 15 et attendre la fin du pull. |
| Import PFX refusé | Vérifier mot de passe, dates, SAN DNS, FQDN, usage serveur, chaîne et paire clé/certificat. |
| Service arrêté au démarrage | Les trois variables `FORTIFLOW_TLS_*` doivent être toutes vides ou toutes renseignées. |
| Clé illisible | Vérifier le montage `/certificates`, le lien `active`, le mode `0640` et le groupe `fortiflow`. |
| Conteneur `unhealthy` | Lire les journaux et vérifier les fichiers TLS, le FQDN et le protocole attendu par le healthcheck. |
| Port 443 inaccessible | Vérifier l’adresse de bind, le firewall, `ss -ltnp` et le mapping `443 -> 3737`. |
| Alerte navigateur | Vérifier FQDN, SAN, dates, chaîne complète et confiance du client dans la CA. |
| Données absentes après MAJ | Vérifier que les trois volumes d’origine sont toujours attachés. Ne pas en créer de nouveaux. |
| Échec juste après MAJ | Conserver les volumes, lire les journaux, corriger les variables ou appliquer le rollback validé. |

Commandes de diagnostic sans modification :

```bash
docker inspect --format '{{json .State}}' fortiflow
docker inspect fortiflow --format \
  '{{range .Mounts}}{{println .Destination "<-" .Name .Source}}{{end}}'
docker port fortiflow 3737
docker logs --tail 150 fortiflow
ss -ltnp
```

> **Règle de sécurité —** Ne lance aucune commande globale de nettoyage Docker et ne supprime aucun volume pour résoudre un problème de déploiement.
