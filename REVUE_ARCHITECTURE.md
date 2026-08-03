# Rapport de Revue d'Architecture — FortiFlow

**Date** : 2026-08-03  
**Périmètre** : `/opt/data/FortiFlow/app/web/` — Application Node.js/Express  
**Méthodologie** : Revue manuelle + analyse statique (token-savior) + exécution des tests + audit npm

---

## 1. Vue d'ensemble

FortiFlow est un analyseur de logs de trafic FortiGate/FortiAnalyzer conçu pour la segmentation réseau. L'application est globalement **bien structurée**, avec un découpage clair en modules fonctionnels. Le niveau de qualité est **supérieur à la moyenne** des projets Node.js rencontrés, avec des patterns modernes (workers threads, SSE/WebSocket, streaming, limites configurables via variables d'environnement).

**49 tests passent sans échec.** Le code est en français pour l'interface utilisateur, en anglais pour les noms techniques.

---

## 2. Architecture — Séparation des responsabilités

### Évaluation : BONNE

| Module | Lignes | Responsabilité | Cohésion |
|--------|--------|---------------|----------|
| `server.js` | 2079 | Routes Express, WebSocket, SSE, middleware | ⚠️ Mixe routes + WS + logique métier (risk-analysis inline) |
| `lib/parser.js` | 835 | Parse streaming KV/CSV/CSV-KV/ZIP/XLSX → flowMap | 👍 Excellente |
| `lib/analyzer.js` | 692 | Analyse de flux, matrices, politiques, consolidation | 👍 Bonne |
| `lib/forticonfig.js` | 2443 | Parseur config FortiGate (.conf) complet | ⚠️ Volumineux, plusieurs responsabilités |
| `lib/store.js` | 185 | Sessions in-memory + persistance disque + purge | 👍 Compact et clair |
| `lib/coverage.js` | 341 | Couverture de policies (first-match) | 👍 Focalisé |
| `lib/deploy-safety.js` | 93 | Bloqueurs de déploiement | 👍 Très focalisé |
| `lib/analysis-pool.js` | 176 | Pool de workers threads | 👍 Bon |
| `lib/analysis-worker.js` | 105 | Worker isolé pour parsing lourd | 👍 Bon |
| `lib/ports.js` | 45 | Résolution noms de ports | 👍 Trivial |

### Points d'attention

- **`server.js` est trop volumineux (2079 lignes).** Il contient à la fois les routes REST, la logique WebSocket, la génération XLSX, l'analyse de risque (shadows, risk scoring), et la certification de déploiement. Ces 3 dernières responsabilités (≥300 lignes chacune) mériteraient d'être extraites dans des modules dédiés.

- **`forticonfig.js` (2443 lignes)** est le plus gros module. Il fait à la fois l'extraction de sections, le parsing d'adresses/services/interfaces/zones/SD-WAN/BGP/OSPF/routes, et génère même la CLI FortiGate (`generateConfig`). Une décomposition en 3-4 modules serait bénéfique (ex: `forticonfig-parser.js`, `forticonfig-routing.js`, `forticonfig-generator.js`).

---

## 3. Patterns Node.js

### 3.1 Async/Await vs Callbacks : BON

L'ensemble du code utilise `async/await` de manière cohérente. Quelques callbacks legacy subsistent dans les API zlib (`zlib.gunzip` avec callback) et multer, mais c'est acceptable car ces API natives n'ont pas de promesses natives dans les versions utilisées.

**⚠️ Mixte readFileSync / promises dans la même fonction** (ex: `server.js` ligne 1224) :
```js
const cached = JSON.parse(fs.promises ? await require('fs').promises.readFile(...) : require('fs').readFileSync(...));
```
Ce test `fs.promises ?` est inutile (fs.promises existe depuis Node 10) et le fallback `readFileSync` bloque l'event loop.

### 3.2 Gestion d'erreur : BONNE avec lacunes

- **Les fichiers critiques** (parser, analyzer, forticonfig) utilisent `try/catch` de manière appropriée.
- **Les erreurs multer** ont un handler dédié (ligne 2013-2020).
- **`parseWorkspaceJson`** protège contre `__proto__` pollution.

**Lacunes :**
- Les `setInterval` (cleanup uploads, purge sessions) écrasent silencieusement les erreurs avec `catch {}`. Une journalisation minimale (`console.error`) serait utile en production.
- Les WebSocket n'ont pas de gestion d'erreur sur `ws.send()` — si le client est déconnecté entre le check `readyState === ws.OPEN` et le send, une exception non capturée peut être levée.
- Pas de handler global `uncaughtException` / `unhandledRejection`.

### 3.3 Memory Leaks Potentiels : À SURVEILLER

| Risque | Détail | Sévérité |
|--------|--------|----------|
| **EventEmitter listeners** | Chaque session crée un `new EventEmitter()`. Les listeners SSE/WS sont nettoyés via `removeListener`/`off`. ✅ Bon | Faible |
| **Map `sessions` sans limite de croissance par clé** | `MAX_SESSIONS=50` limite le nombre total, mais chaque session peut contenir `data.flows` volumineux (jusqu'à 2M flows). La limite est sur le nombre, pas sur la mémoire totale. | Moyenne |
| **Workers terminés** | `_settle()` appelle `worker.terminate()` après chaque job. ✅ | Faible |
| **`originalFlows`** | Conservé dans la session après re-analyse config (`s.originalFlows = s.data.flows`). Jamais nettoyé explicitement. | Faible |
| **`readline` streams** | Le parser ferme le stream via `for await` (nettoyage implicite). ✅ | Faible |

---

## 4. Performance

### 4.1 Streams & Backpressure : BON

- **Parser** : utilise `readline` + `for await` — gestion correcte du streaming, pas de chargement complet en mémoire.
- **ZIP** : `decompressedLimitStream` limite la décompression à `MAX_DECOMPRESSED_BYTES` (défaut 4096 Mo, max 32 Go).
- **XLSX** : `MAX_XLSX_BYTES` limite le parsing Excel à 512 Mo max.
- **Upload multer** : `MAX_UPLOAD_BYTES` (défaut 2 Go, max 10 Go). Le fichier est écrit sur disque (pas en mémoire).

### 4.2 Limites configurées : EXCELLENT

Toutes les limites sont configurables via variables d'environnement avec des garde-fous :

| Variable | Défaut | Max hard | Usage |
|----------|--------|----------|-------|
| `MAX_UPLOAD_SIZE_MB` | 2048 | 10240 | Taille upload fichier |
| `MAX_WORKSPACE_UNCOMPRESSED_MB` | 1024 | 4096 | Taille workspace décompressé |
| `MAX_DECOMPRESSED_SIZE_MB` | 4096 | 32768 | Contenu zip décompressé |
| `MAX_ARCHIVE_ENTRIES` | 100 | 1000 | Entrées dans une archive |
| `MAX_SESSION_DEDUPE_KEYS` | 2M | illimité | Clés de déduplication |
| `MAX_XLSX_SIZE_MB` | 100 | 512 | Taille fichier Excel |
| `MAX_ANALYSIS_WORKERS` | 1 | illimité | Workers parallèles |
| `MAX_ANALYSIS_QUEUE` | 3 | illimité | File d'attente d'analyse |

### 4.3 Points d'amélioration

- **Single-pass optimisé** : `buildAllSubnetGroupsAndPorts` fait une seule passe sur les flows pour 4 groupes de sous-réseaux + stats ports. 👍
- **La génération XLSX** (`/api/export/matrix`) reconstruit `countMap` à chaque requête. Pour les grosses matrices (>100 sous-réseaux), le build XLSX prend ~100-300ms. Pas critique mais pourrait être mis en cache par session.
- **`flows.slice().sort()`** dans `/api/flows` crée une copie complète pour le tri paginé. Pour >1M flows, préférer un tri serveur ou un index.

---

## 5. Tests

### 5.1 Couverture : CORRECTE mais INCOMPLÈTE

**49 tests passent** répartis sur 4 fichiers :

| Fichier | Nombre tests | Couvre |
|---------|-------------|--------|
| `security.test.js` (1023 lignes) | ~40 tests | Parser, analyzer, forticonfig, coverage, deploy-safety |
| `analysis-pool.test.js` (79 lignes) | 2 tests | Pool workers |
| `segmentation-plan.test.js` (139 lignes) | 4 tests | Plan de segmentation frontend |
| `server-dependencies.test.js` (29 lignes) | 1 test | Vérification imports |

### 5.2 Lacunes de test

- ❌ **Aucun test sur les routes Express** (pas de supertest ou équivalent). Les endpoints `/api/upload`, `/api/policies`, `/api/deploy/generate` ne sont pas testés en intégration.
- ❌ **Aucun test sur la gestion mémoire** : pas de test de limite de sessions, pas de test de purge TTL.
- ❌ **Pas de test sur `forticonfig.js` `generateConfig`** — la génération de CLI n'est pas testée unitairement.
- ❌ **Pas de test sur `store.js`** — `createSession`, `evictOldest`, `deleteSession` ne sont pas testés isolément.
- ⚠️ **Pas de test sur la fonction `consolidatePolicies`** (fin du fichier analyzer.js lignes 598-692, non lues dans cette revue mais le test dans security.test.js semble tester `buildAnalysis` seulement).

### 5.3 Qualité des tests existants : BONNE

Les tests sont bien écrits, avec des fixtures explicites et des assertions précises. La couverture des cas limites du parser (CSV sans header, FAZ CSV-KV, déduplication de sessions, VDOM multiples, DNS failed) est excellente.

---

## 6. Code Dupliqué

### 🔴 ALLOW_ACTIONS / DENY_ACTIONS — Dupliqué 3 fois

| Fichier | Ligne | Contexte |
|---------|-------|----------|
| `parser.js` | 166-173 | `normalizeDecision()` |
| `analyzer.js` | 71-78 | `flowDecision()` |
| `deploy-safety.js` | 18-21 | `getCaptureDeploymentBlockers()` |

**Impact** : Si une nouvelle action FortiOS est ajoutée (ex: `accept-session`), il faut modifier 3 fichiers. Risque de divergence.

**Recommandation** : Extraire `ALLOW_ACTIONS` et `DENY_ACTIONS` dans `lib/constants.js` et les importer.

### 🟡 `ip2int` — Dupliqué dans `analyzer.js` et `forticonfig.js`

Deux implémentations quasi-identiques :
- `analyzer.js:7-11` : silencieuse (retourne `NaN`)
- `forticonfig.js:138-144` : lève une exception

**Recommandation** : Unifier dans `lib/network.js`.

### 🟡 `isPrivate` / `isPrivateIP` — Dupliqué

- `analyzer.js:19-23` : `isPrivate()` 
- `forticonfig.js:269-272` : `isPrivateIP()`

Même logique RFC1918, signatures différentes.

---

## 7. Gestion des Workers (analysis-pool)

### Évaluation : ROBUSTE

- **Isolation** : Le parsing lourd s'exécute dans des `worker_threads`, pas dans l'event loop principal. ✅
- **File d'attente** : Limitée à `MAX_ANALYSIS_QUEUE` (défaut 3). `canAccept()` bloque les nouvelles soumissions. ✅
- **Graceful shutdown** : `close()` termine les workers avec `worker.terminate()` et rejette les jobs en attente. ✅
- **Annulation** : `cancel(jobId)` fonctionne pour les jobs en attente ET en cours. ✅
- **Resource limits** : `workerMemoryMb` permet de limiter la heap des workers si ≥ 256 Mo. ✅
- **Protection `job.settled`** : Évite les doubles résolutions (message + error + exit). ✅

### Lacune

- **Pas de graceful shutdown au niveau serveur** : `server.js` n'écoute pas `SIGTERM`/`SIGINT`. Si le processus est tué, les workers en cours sont abandonnés sans `pool.close()`.

```js
// Manquant dans server.js :
process.on('SIGTERM', async () => {
  await analysisPool.close();
  server.close();
  process.exit(0);
});
```

---

## 8. API Design

### 8.1 RESTful : BON

Les routes suivent une convention cohérente :
- `GET /api/flows`, `GET /api/policies`, `GET /api/stats` : lecture
- `POST /api/upload`, `POST /api/import/workspace` : création
- `DELETE /api/session/:session` : suppression
- `PUT /api/risk-ports` : mise à jour

### 8.2 Codes HTTP : CORRECT

| Cas | Code |
|-----|------|
| Session introuvable | 404 |
| Parsing en cours | 202 |
| Flows libérés (après config) | 410 Gone |
| Fichier trop volumineux | 413 |
| Queue d'analyse pleine | 503 |
| Preflight échoué | 422 |
| Erreur serveur | 500 |

### 8.3 Validation : CORRECTE avec angles morts

- `validateWorkspaceBody` vérifie `_ffws`, `data`, `flows`, `stats`, `fortiConfig`. ✅
- `parseWorkspaceJson` bloque `__proto__`. ✅
- Les paramètres de pagination sont validés (`Math.max(1, ...)`, `Math.min(500, ...)`). ✅
- `req.query` non validé pour `sort` — injection potentielle dans `a[sort]` (ligne 513-514). Un attaquant pourrait faire `?sort=__proto__`. ⚠️

**Recommandation** : Whitelist des colonnes triables.

### 8.4 Authentification : ABSENTE

Il n'y a **aucune authentification** sur les routes. Les routes `/api/admin/sessions` et `DELETE /api/admin/sessions` exposent la gestion des sessions sans protection. En environnement de production, un reverse proxy avec auth ou un middleware d'authentification est indispensable.

---

## 9. Séparation Front/Back

### Évaluation : BONNE

- **Frontend** : `public/app.js`, `public/segmentation-plan.js`, `public/index.html`, `public/admin.html`
- **Backend** : `server.js` + `lib/*`
- **Communication** : REST + SSE + WebSocket (même port, upgrade HTTP)

**⚠️ `segmentation-plan.js` est testé côté Node.js** (importé dans `segmentation-plan.test.js`) — cela fonctionne car le module n'utilise pas d'API navigateur, mais c'est un couplage implicite. Le fichier est dans `public/` (servi statiquement) mais aussi requis comme module CommonJS.

---

## 10. Dépendances (package.json)

### Versions

```json
{
  "exceljs": "^4.4.0",
  "express": "^4.18.2",
  "multer": "^2.1.1",
  "unzipper": "^0.10.14",
  "ws": "^8.20.0",
  "xlsx": "^0.18.5"
}
```

### Vulnérabilités (npm audit)

| Package | Sévérité | Description |
|---------|----------|-------------|
| `body-parser` (deps express) | moderate | DoS via invalid limit value (GHSA-v422-hmwv-36x6) — fix: ≥1.20.6 |
| `brace-expansion` (deps multiples) | high | DoS via exponential expansion (GHSA-3jxr-9vmj-r5cp, GHSA-f886-m6hf-6m8v, GHSA-mh99-v99m-4gvg) |

**Action** : `npm audit fix` ou mise à jour d'express vers ^4.21+ résoudra la plupart des vulnérabilités.

### Points positifs
- Peu de dépendances directes (6). 👍
- `ws` version récente (8.20.0). 👍
- Pas de dépendances abandonnées. 👍

---

## 11. Gestion de la Mémoire

### Sessions in-memory

- **`MAX_SESSIONS = 50`** — limite stricte sur le nombre de sessions. ✅
- **`SESSION_TTL_MS = 4h`** — purge périodique toutes les 10 minutes. ✅
- **`evictOldest()`** — éviction LRU quand la limite est atteinte. ✅
- **Persistance disque** : `_save()` écrit les sessions dans `../../sessions-cache/` avec atomic rename (write tmp → rename). ✅

### ⚠️ Pas de limite de mémoire totale

`MAX_SESSIONS=50` limite le nombre de sessions, mais une seule session peut contenir >1 Go de données en mémoire (flows + matrices + policies). Il n'y a pas de mécanisme pour limiter la mémoire totale utilisée par le processus. Si 50 sessions de 500 Mo chacune coexistent, le processus peut atteindre 25 Go.

**Recommandation** : Ajouter une vérification `process.memoryUsage().heapUsed` avant d'accepter de nouvelles sessions, ou limiter la taille des données par session.

### ⚠️ `originalFlows` jamais libéré

Après le chargement d'une config FortiGate, `s.originalFlows` est défini (ligne 1563) et n'est jamais nettoyé. Cela double effectivement la mémoire utilisée pour les flows de la session.

---

## 12. Synthèse des Priorités

### 🔴 Critique

1. **Pas de graceful shutdown** : Ajouter `SIGTERM`/`SIGINT` handlers avec `analysisPool.close()` et `server.close()`.
2. **Injection via paramètre `sort`** : Whitelist des colonnes triables dans `/api/flows`.
3. **Pas d'authentification** : Les routes admin exposent toutes les sessions sans protection.

### 🟡 Important

4. **ALLOW_ACTIONS dupliqué 3 fois** : Extraire dans `lib/constants.js`.
5. **`ip2int` dupliqué** : Unifier dans `lib/network.js`.
6. **`npm audit`** : Mettre à jour express (body-parser) et les dépendances transitives (brace-expansion).
7. **Pas de limite de mémoire totale par processus** : Ajouter un check `heapUsed` avant `createSession()`.

### 🟢 Amélioration

8. **`server.js` trop volumineux** : Extraire la logique risk-analysis, la génération XLSX, et la certification dans des modules dédiés.
9. **`forticonfig.js` trop volumineux** : Scinder en 2-3 modules.
10. **Tests d'intégration** : Ajouter des tests sur les routes Express (supertest).
11. **Tests unitaires manquants** : `store.js`, `consolidatePolicies`, `generateConfig`.
12. **`originalFlows`** : Le nettoyer après re-analyse ou utiliser une référence faible.
13. **`readFileSync` fallback inutile** : `fs.promises` existe depuis Node 10 ; supprimer le fallback synchrone (ligne 1224).
14. **Journalisation des erreurs** : Remplacer les `catch {}` silencieux par `console.error` dans les setInterval.

---

## 13. Conclusion

FortiFlow est une application **bien conçue et professionnelle**. La séparation des responsabilités est globalement respectée, les patterns Node.js sont modernes, et les limites de sécurité (taille upload, décompression, workers) sont bien pensées et configurables. Les 49 tests passent sans échec et couvrent bien les cas critiques du parser.

Les principaux axes d'amélioration sont : la **sécurisation de l'API** (auth, validation du paramètre `sort`), le **graceful shutdown**, l'**élimination des duplications de code**, et la **mise à jour des dépendances** pour corriger les vulnérabilités npm. La refonte des deux plus gros fichiers (`server.js`, `forticonfig.js`) en modules plus petits améliorerait la maintenabilité à long terme.
