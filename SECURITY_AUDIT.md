# Rapport de sécurité — FortiFlow

**Date** : 2026-08-03
**Cible** : `/opt/data/FortiFlow` @ `main` (8ede5fb)
**Périmètre** : `server.js`, `parser.js`, `deploy-safety.js`, `entrypoint.sh`, `Dockerfile`, `docker-compose.yml`, `store.js`, `forticonfig.js` (preflightValidation, generateConfig)
**Méthodologie** : Revue statique fail-closed, traçage des frontières de confiance, vérification des invariants documentés dans README.md

---

## SYNTHÈSE

| Sévérité | Nombre | Impact |
|----------|--------|--------|
| **CRITICAL** | 1 | Absence totale d'authentification — routes admin exposées |
| **HIGH** | 1 | Pas de rate limiting — brute-force session ID envisageable |
| **MEDIUM** | 4 | Prototype pollution, race session, upload non validé, Docker hardening |
| **LOW** | 3 | CSP/HSTS manquants, race workspace, erreurs exposées |

**Verdict** : Le modèle fail-closed de génération des règles firewall est **robuste et bien implémenté**. Les invariants documentés dans le README sont tous vérifiés par du code réel (preflight + deploy-safety + hard throws dans generateConfig). En revanche, l'application n'a **aucune couche d'authentification** — une faille critique pour un outil qui génère des règles firewall, même en environnement interne de confiance. Les risques d'injection sont globalement bien maîtrisés.

---

## DÉTAILS PAR CATÉGORIE

### 1. INJECTION

#### 1.1 Prototype pollution — JSON body non protégé sur la plupart des routes
- **Sévérité** : MEDIUM
- **Fichier** : `app/web/server.js`, ligne 156
- **Description** : `express.json({ limit: '50mb' })` parse tous les corps JSON sans reviver anti-prototype-pollution. Le workspace import (`/api/import/workspace`) est protégé via `parseWorkspaceJson()` (lignes 225-232) qui rejette `__proto__`, `prototype`, `constructor`. Mais les autres routes POST/PUT comme `/api/deploy/config-vdom`, `/api/deploy/dynamic-routes`, `/api/deploy/preflight`, `/api/workspaces` n'ont pas cette protection.
- **Exploitation** : Un attaquant pourrait envoyer `{"__proto__": {"isAdmin": true}}` à une route acceptant du JSON et potentiellement corrompre le prototype d'Object.
- **Recommandation** : Appliquer un reviver anti-prototype-pollution globalement dans un middleware, ou utiliser `JSON.parse` avec un reviver systématiquement.

#### 1.2 Pas d'injection de chemin (path traversal) — OK
- **Fichier** : `app/web/server.js`, lignes 129-138
- **Analyse** : Les noms de fichiers uploadés sont filtrés via `path.basename()` puis `replace(/[^a-zA-Z0-9._-]/g, '_')`. Les identifiants de workspace sont générés par `crypto.randomBytes(8).toString('hex')`. Aucune concaténation de paramètres utilisateur dans des chemins sans assainissement.

#### 1.3 Pas d'injection de commande — OK
- **Analyse** : Aucun appel à `exec()`, `spawn()`, ou `child_process`. La génération CLI produit du texte pur, jamais exécuté.

#### 1.4 CSV injection mitigée — OK
- **Fichier** : `app/web/server.js`, lignes 343-362
- **Analyse** : `sendCsv()` préfixe les valeurs commençant par `=`, `+`, `-`, `@` avec `'` pour neutraliser l'interprétation comme formule Excel/LibreOffice. Correct.

#### 1.5 XSS dans les réponses API — risque faible
- **Analyse** : Toutes les routes API renvoient du JSON (`Content-Type: application/json`). Le contenu statique est servi via `express.static`. Les commentaires CLI sont assainis par `cliCommentText()` (lignes 25-28). Le frontend (hors scope) pourrait être vulnérable si les noms de policies ou adresses sont injectés dans le DOM sans échappement.

---

### 2. AUTHENTIFICATION / ACL

#### 2.1 ABSENCE TOTALE D'AUTHENTIFICATION
- **Sévérité** : **CRITICAL**
- **Fichier** : `app/web/server.js`, global
- **Description** : Aucun mécanisme d'authentification : pas de login, pas de mot de passe, pas de token, pas de session utilisateur. Les « sessions » dans le code sont des conteneurs de données d'analyse, pas des sessions authentifiées. Toute personne ayant accès réseau à l'instance peut :
  - Uploader des logs et créer des sessions (POST `/api/upload`)
  - Consulter TOUTES les sessions actives (GET `/api/admin/sessions`)
  - Supprimer n'importe quelle session (DELETE `/api/admin/sessions/:id`)
  - Supprimer TOUTES les sessions (DELETE `/api/admin/sessions`)
  - Modifier la configuration des ports à risque (PUT `/api/risk-ports`)
  - Générer et télécharger des configurations FortiGate (POST `/api/deploy/generate`)
- **Contexte** : Le README indique « L'instance est prévue pour un environnement interne de confiance » et le docker-compose bind sur `127.0.0.1:13737`. Ces mesures réseau sont nécessaires mais pas suffisantes — la défense en profondeur exige une authentification applicative.
- **Recommandation** : Implémenter a minima une authentification basique (HTTP Basic Auth, token statique en variable d'environnement, ou client TLS). Protéger les routes `/api/admin/*` et `/api/deploy/*` par un middleware d'authentification.

#### 2.2 Absence de rate limiting
- **Sévérité** : HIGH
- **Fichier** : `app/web/server.js`, global
- **Description** : Aucun rate limiting sur aucune route. Un attaquant peut brute-forcer les IDs de session (32 caractères hexadécimaux = 128 bits, mais sans rate limit, une attaque massive est possible). Les routes d'upload et de génération sont également non limitées.
- **Recommandation** : Ajouter `express-rate-limit` avec des limites par IP sur les routes sensibles (upload, generate, admin).

---

### 3. GESTION DES SECRETS

#### 3.1 Aucun secret hardcodé — OK
- **Analyse** : Aucun mot de passe, clé API, token ou secret trouvé dans le code source. Les chemins SSL sont configurables via variables d'environnement.

#### 3.2 Session ID exposé dans les URLs et query params
- **Sévérité** : LOW
- **Fichier** : `app/web/server.js`, lignes 218, 459, 1504
- **Description** : Le `sessionId` est passé en query parameter (`?session=...`) ou path parameter (`/:session`). Cela signifie qu'il apparaît dans les logs serveur, les logs proxy, et l'historique navigateur.
- **Recommandation** : Utiliser un header HTTP ou un cookie pour transporter l'ID de session plutôt que l'URL.

---

### 4. VALIDATION DES ENTRÉES

#### 4.1 Upload — pas de validation d'extension
- **Sévérité** : MEDIUM
- **Fichier** : `app/web/server.js`, lignes 129-138
- **Description** : `multer` accepte tout type de fichier. La validation du format n'arrive que dans `parseFile()` qui vérifie l'extension pour choisir le parser. Un fichier `.exe` ou `.php` uploadé restera sur disque dans `uploads/` jusqu'au nettoyage périodique (1h) ou démarrage.
- **Recommandation** : Ajouter un `fileFilter` dans la configuration multer pour n'accepter que les extensions autorisées (`.log`, `.csv`, `.txt`, `.gz`, `.zip`, `.xlsx`, `.xls`).

#### 4.2 Workspace import — bien validé — OK
- **Fichier** : `app/web/server.js`, lignes 225-251
- **Analyse** : `validateWorkspaceBody` vérifie `_ffws === 2`, structure, types, et limite de 2M flows. `parseWorkspaceJson` bloque les clés prototype. La taille décompressée est limitée via `zlib.gunzip` avec `maxOutputLength`. Bon.

#### 4.3 JSON body size — très permissif
- **Sévérité** : MEDIUM
- **Fichier** : `app/web/server.js`, ligne 156
- **Description** : `express.json({ limit: '50mb' })` appliqué globalement. Certaines routes n'ont besoin que de quelques KB (ex: `/api/deploy/config-vdom` accepte juste `{vdom: "..."}`). Un attaquant peut envoyer 50 MB de JSON à n'importe quelle route POST.
- **Recommandation** : Appliquer des limites différenciées par route (ex: 10kb pour config-vdom, 50mb pour l'export policies-xlsx, 300mb pour workspace import).

#### 4.4 WebSocket — pas de validation d'origine
- **Sévérité** : LOW
- **Fichier** : `app/web/server.js`, lignes 2030-2060
- **Description** : Le WebSocket `/ws/progress` accepte les connexions sans vérifier l'en-tête `Origin`. En l'absence d'authentification, cela permet à n'importe quel site web de se connecter au WebSocket (CSWSH — Cross-Site WebSocket Hijacking).
- **Recommandation** : Vérifier l'en-tête `Origin` dans le handler `upgrade`.

---

### 5. FAIL-CLOSED — VÉRIFICATION DES INVARIANTS

**Verdict : TOUS les invariants documentés dans le README sont implémentés et vérifiés.**

| Invariant README | Implémentation | Fichier/ligne |
|---|---|---|
| Actions inconnues exclues | `normalizeDecision()` → 'unknown', bloqué par `deploy-safety.js:48` | parser.js:175, deploy-safety.js:48 |
| VDOM jamais fusionnés | Clé d'agrégation inclut `devid\|vdom` | parser.js:479 |
| dstaddr "all" WAN = choix explicite | Preflight error si WAN sans dst spécifique, warn si explicite | forticonfig.js:2189-2199 |
| Service exact requis pour réutilisation | Preflight vérifie `service.found` ou définition exacte | forticonfig.js:2219-2238 |
| Pas de repli implicite vers service ALL / srcaddr all | Erreurs bloquantes preflight | forticonfig.js:2210-2218 |
| Flux non-forward/NATés = pas de règles | `evidenceIssues` → `deploymentEligible: false` | parser.js:362-388, deploy-safety.js:22-26 |
| ECMP non résolu arbitrairement | Routes triées, warning si ambigu | forticonfig.js (routing) |
| Routes désactivées ignorées | Filtrage dans `parseFortiConfig` | Vérifié par test |
| Ordre first-match conservé | Conservation de l'ordre d'édition FortiOS | Vérifié par test |
| VRF non-défaut bloque | Preflight error | forticonfig.js:2125-2131 |
| IPv6/invalide/partiel bloque | `deploy-safety.js` → `blocked: true` | deploy-safety.js:44-82 |
| Preflight systématique avant CLI | Appelé dans `/api/deploy/generate` | server.js:1776-1888 |
| Certification exact/généralisé | Calculé dans preflight, rapporté dans CLI | forticonfig.js:2119-2122 |

**Note supplémentaire** : `generateConfig()` dans `forticonfig.js` lève des exceptions dures (`throw new Error(...)`) pour toute condition invalide — pas de fallback silencieux. C'est une implémentation fail-closed correcte.

---

### 6. RACE CONDITIONS / TOCTOU

#### 6.1 Session store non atomique
- **Sévérité** : MEDIUM
- **Fichier** : `app/web/lib/store.js`, global
- **Description** : Les opérations sur la `Map` sessions ne sont pas protégées par un mutex. Deux requêtes concurrentes sur la même session peuvent causer des corruptions (ex: `setSessionData` pendant que `deleteSession` libère `s.data`). Le cache disque utilise `writeFile` + `rename` (quasi-atomique sur POSIX), mais la Map mémoire n'est pas protégée.
- **Recommandation** : Sérialiser les mutations par session avec un lock simple (ex: `async-mutex` ou une file de promesses par session ID).

#### 6.2 Workspace index race
- **Sévérité** : LOW
- **Fichier** : `app/web/server.js`, lignes 106-111
- **Description** : `loadWsIndex()` + `saveWsIndex()` sont des opérations read-modify-write sans lock. Deux sauvegardes concurrentes perdent les données de l'une d'elles. Impact faible : historique des workspaces.
- **Recommandation** : Utiliser un fichier lock ou une file d'écriture.

#### 6.3 Fichiers uploadés — pas de TOCTOU
- **Analyse** : Le fichier est écrit par multer, le `filePath` est capturé immédiatement, et le traitement est confié à `analysisPool`. Pas de fenêtre entre check et use.

---

### 7. SÉCURITÉ DOCKER

#### 7.1 Hardening insuffisant du conteneur
- **Sévérité** : MEDIUM
- **Fichier** : `docker-compose.yml`, `Dockerfile`
- **Description** :
  - Pas de `read_only: true` sur le rootfs (seuls les volumes sont en lecture seule)
  - Pas de `cap_drop: [ALL]` (le conteneur garde toutes les capacités par défaut)
  - Pas de `security_opt: [no-new-privileges:true]`
  - Le processus principal tourne en `fortiflow` (non-root) après l'entrypoint, ce qui est correct
  - Bind sur `127.0.0.1:13737` — bonne pratique
- **Recommandation** : Ajouter dans docker-compose.yml :
  ```yaml
  read_only: true
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  ```
  S'assurer que les volumes `sessions-cache`, `workspaces`, `uploads` sont en `:rw`.

#### 7.2 Entrypoint privilege drop correct — OK
- **Fichier** : `app/web/entrypoint.sh`
- **Analyse** : `chown -R fortiflow:fortiflow` (avec `|| true` pour les volumes non montés), puis `exec su-exec fortiflow node server.js`. Le `exec` remplace le processus shell, pas de processus root résiduel. Correct.

---

### 8. CORS / HEADERS DE SÉCURITÉ

#### 8.1 Headers de sécurité manquants
- **Sévérité** : LOW
- **Fichier** : `app/web/server.js`, lignes 142-148
- **Description** : Les headers suivants sont absents :
  - `Content-Security-Policy`
  - `Strict-Transport-Security` (HSTS) — pertinent si HTTPS activé
  - `X-XSS-Protection` (défense en profondeur, bien que déprécié)
  - `Cross-Origin-Resource-Policy`
- **Headers présents** : `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: same-origin`, `Permissions-Policy` restrictif. Bonne base.
- **Recommandation** : Ajouter CSP et HSTS. Pour un outil interne, une CSP `default-src 'self'` est suffisante.

#### 8.2 Pas de CORS configuré
- **Sévérité** : LOW
- **Fichier** : `app/web/server.js`
- **Description** : Aucun middleware CORS. Le frontend est servi par le même serveur (same-origin), donc les requêtes navigateur fonctionnent. Mais l'absence de `Access-Control-Allow-Origin` explicite est correcte pour une app same-origin — aucun risque de CORS non contrôlé.
- **Analyse** : Acceptable en l'état pour une application interne. Si l'API devait être consommée par un frontend séparé, il faudrait configurer CORS avec une origine explicite.

---

## TABLEAU RÉCAPITULATIF

| # | Sévérité | Fichier | Ligne(s) | Description |
|---|----------|---------|----------|-------------|
| 1 | **CRITICAL** | server.js | global | Absence totale d'authentification — routes admin et deploy non protégées |
| 2 | **HIGH** | server.js | global | Absence de rate limiting — brute-force possible sur session IDs |
| 3 | **MEDIUM** | server.js | 156 | Prototype pollution via JSON body sur la plupart des routes |
| 4 | **MEDIUM** | server.js | 129-138 | Upload sans validation d'extension — fichiers arbitraires acceptés |
| 5 | **MEDIUM** | store.js | global | Mutations de session non atomiques — corruption possible en accès concurrent |
| 6 | **MEDIUM** | docker-compose.yml | global | Hardening Docker insuffisant — rootfs RW, pas de cap_drop, pas de no-new-privileges |
| 7 | **LOW** | server.js | 156 | Limite JSON body uniforme de 50 MB sur toutes les routes |
| 8 | **LOW** | server.js | 142-148 | Headers CSP et HSTS manquants |
| 9 | **LOW** | server.js | 106-111 | Race condition sur l'index des workspaces |

---

## POINTS FORTS

1. **Modèle fail-closed exemplaire** : Tous les invariants de sécurité documentés dans le README sont tracés jusqu'au code. Les contrôles sont redondants (preflight + deploy-safety + throws dans generateConfig).
2. **Parsing robuste** : La déduplication FortiOS, la gestion des sessions réutilisées, la classification des échecs DNS, et la ségrégation VDOM/équipement sont remarquablement soignés.
3. **Pas de secrets hardcodés** : Aucun mot de passe, token, ou clé trouvé dans le code.
4. **Validation workspace** : Double protection anti-prototype-pollution + validation structurelle + limite de taille.
5. **Tests de sécurité** : 1023 lignes de tests couvrant explicitement les invariants fail-closed (actions inconnues, VDOM, NAT, protocoles déduits, ordre first-match, etc.).
6. **Isolation réseau** : Bind sur localhost uniquement, pas d'exposition directe.

## POINTS D'AMÉLIORATION PRIORITAIRES

1. **Ajouter une authentification** — Même basique (HTTP Basic Auth avec un secret partagé en variable d'environnement). C'est le point bloquant critique.
2. **Ajouter du rate limiting** — Au minimum sur les routes admin et d'upload.
3. **Durcir le conteneur Docker** — `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`.
4. **Protéger toutes les routes JSON contre le prototype pollution** — Middleware global avec reviver.
5. **Valider les extensions de fichiers uploadés** — Whitelist dans le `fileFilter` de multer.
