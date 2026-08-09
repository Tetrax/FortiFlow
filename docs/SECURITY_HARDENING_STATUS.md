# FortiFlow — suivi des corrections de l’audit

Ce document décrit les décisions prises dans la branche de durcissement. Il ne
modifie pas le périmètre accepté : **aucune authentification applicative n’est
ajoutée**. L’instance reste protégée par le firewall/reverse proxy externe,
comme décidé pour FortiFlow.

## Rate limiting — FIXED

- Le limiteur fixe une fenêtre de 20 requêtes par minute et est enregistré avant
  `express.json`, `multer` et les routes `/api/upload` et `/api/admin`.
- Un rejet `429` ne déclenche donc ni parsing JSON, ni écriture multipart sur
  disque, ni traitement d’analyse.
- `FORTIFLOW_TRUST_PROXY` accepte une liste explicite d’adresses IP/CIDR des
  proxys de confiance. Express ne traite `X-Forwarded-For` comme adresse client
  que pour ces proxys.
- La configuration Nginx fournie écrase `X-Forwarded-For` avec `$remote_addr`
  (et ne relaie pas un XFF fourni par le client) avant que Node ne le lise.
- Dans la topologie Docker avec port hôte publié sur loopback, l'adresse source
  vue par le conteneur est généralement la gateway du bridge Docker (par
  exemple `172.17.0.1`), pas `127.0.0.1`. La valeur exacte doit être mesurée sur
  l'hôte puis configurée explicitement ; elle peut varier selon le réseau
  Compose/Portainer.
- La valeur vide est volontairement le défaut sûr : un en-tête
  `X-Forwarded-For` direct est ignoré. Derrière un proxy non déclaré, les
  clients partagent alors le compartiment de l’adresse du proxy (risque de
  disponibilité, pas contournement de la limite) ; il faut renseigner l’adresse
  source réelle du proxy dans `.env`.
- Ne pas configurer `FORTIFLOW_TRUST_PROXY=*` ou `true` lorsque le port interne
  est joignable directement.

## Dépendances ciblées — FIXED

- `multer` : `2.1.1` → `2.2.0` (corrige les deux avis Multer présents dans
  `npm audit`).
- `ws` : `8.20.0` → `8.21.3` (version corrigée au-delà des plages des avis
  mémoire/DoS).
- Les versions sont présentes dans `package.json` et `package-lock.json` et
  ont été installées par une commande ciblée `npm install --save
  multer@2.2.0 ws@8.21.3`, jamais par `npm audit fix`.

## `xlsx` 0.18.5 — DEFERRED

Usage retracé : `app/web/lib/parser.js:parseXLSX` charge dynamiquement `xlsx`,
lit la première feuille, convertit les lignes avec `sheet_to_json`, et prend
en charge les extensions `.xlsx` **et `.xls`**. L’import est donc fonctionnel
et couvert par le chemin d’analyse worker.

`npm audit --omit=dev` signale :

- [GHSA-4r6h-8v6p-xvw6](https://github.com/advisories/GHSA-4r6h-8v6p-xvw6) — prototype pollution ;
- [GHSA-5pgg-2g8v-p4x9](https://github.com/advisories/GHSA-5pgg-2g8v-p4x9) — ReDoS ;
- `fixAvailable: false` pour le paquet `xlsx` publié sur npm (`0.18.5` est
  également sa dernière version publiée dans cette source).

Le fork `@e965/xlsx` (`0.20.3`) a été examiné : il se présente comme une
republication communautaire de SheetJS, mais sa publication npm la plus
récente observée date de 2024-07-19 et il ne constitue pas une dépendance
maintenue et validée suffisante pour un remplacement de sécurité sans
validation fonctionnelle. `exceljs` est déjà installé mais documente la lecture
XLSX/JSON, pas le format `.xls`, et son API n’est pas un remplacement
transparent du code actuel.

Décision : ne pas casser les imports XLSX/XLS ni introduire un fork non validé.
Mitigations maintenues : limite `MAX_XLSX_SIZE_MB` par défaut à 100 MiB (hard
max 512 MiB), traitement dans le worker d’analyse, limite d’upload globale,
firewall/reverse proxy et rate limiting. Une migration future devra apporter
un parseur maintenu couvrant les deux formats et des tests de fixtures
équivalents avant suppression de `xlsx`.

## Limite d’upload 2 Gio — ACCEPTED RISK / MAINTAINED

La limite par défaut `MAX_UPLOAD_SIZE_MB=2048` n’est pas arbitraire :

- le commit `1ae638b` a remplacé l’ancien plafond de 400 MiB par une limite
  configurable dont le défaut est 2048 MiB ;
- le commit `021e1d2` a provisionné explicitement 2 Go dans Docker ;
- `infra/nginx/fortiflow.conf` fixe aussi `client_max_body_size 2048m` ;
- le README recommande des fichiers proches de 1–2 Go pour les gros exports
  FortiAnalyzer.

Le fichier est écrit en streaming sur disque, le timeout d’upload est de 30
minutes, et l’analyse lourde est isolée dans un worker avec une file bornée.
La valeur est configurable (`1..10240` MiB) et les formats XLSX ont une limite
mémoire séparée. La conserver préserve le besoin métier des exports FAZ ; elle
n’est donc pas réduite dans cette correction.

Les tests HTTP vérifient les bornes avec `MAX_UPLOAD_SIZE_MB=1` et des buffers de
1 MiB, sans créer de fichier géant : juste sous la limite → `200`, au-dessus →
`413`.

## CI — FIXED / POLICY DOCUMENTED

- `npm audit --omit=dev --audit-level=critical` est exécuté dans la CI : les
  vulnérabilités CRITICAL bloquent, tandis que les HIGH/MODERATE restent
  visibles dans le journal sans rendre la CI définitivement rouge pour un avis
  sans correctif.
- Trivy bloque les vulnérabilités CRITICAL corrigibles (`ignore-unfixed: true`)
  et produit un rapport HIGH informatif (`exit-code: 0`). Le job n’est plus
  globalement `continue-on-error`.
- Les avis npm non résolus restent explicitement suivis. Après la mise à niveau
  ciblée, l’audit de production passe de 11 avis (6 HIGH, 5 MODERATE) à 9 avis
  (4 HIGH, 5 MODERATE) ; les avis Multer et ws disparaissent. Aucun CRITICAL
  n’est présent dans l’audit observé.

## Preuves de test

- Test RED puis GREEN : `app/web/test/rate-limit.test.js` reproduit le défaut
  d’ordre (pas de `429` avant la correction), puis vérifie `/api/admin`,
  `/api/upload`, le proxy approuvé/non approuvé et les bornes d’upload.
- La suite existante et les tests HTTP sont exécutés par `npm test`.
- Les checks `node --check` sont conservés dans la CI pour les fichiers
  JavaScript pertinents.
