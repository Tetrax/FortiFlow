# Network Representation Resolver — backend pur

## Statut

Le resolver de phase 2 est un module backend indépendant :

```text
app/web/lib/network-representation-resolver.js
```

Il reçoit une policy V2 exacte et une configuration FortiGate déjà parsée. Il retourne uniquement des suggestions. Il n'importe pas Policy Engine V2, ne modifie pas la policy, n'appelle ni preflight, ni API, ni générateur CLI.

## Entrée

La policy doit porter au minimum :

- `sources` et `destinations` IPv4 exactes ;
- `serviceKeys` techniques ;
- partition équipement/VDOM/interfaces ;
- identifiant et, si disponible, trace des FlowAtoms.

Le côté résolu est explicite : `source` ou `destination`.

## Contrats runtime

Version de schéma : `1`. Version resolver : `1.0.0`.

Les frontières sont validables indépendamment :

- `validateNetworkCandidate()` ;
- `validateExistingFortiObjectMatch()` ;
- `validateExactGroupCandidate()` ;
- `validateCIDRCandidate()` ;
- `validateResolutionResult()`.

### NetworkCandidate

Tous les candidats exposent :

- identité déterministe fondée sur la membership technique ;
- policy fingerprint et côté source/destination ;
- type, rang, origine et objets concernés ;
- IP/CIDR représentés ;
- cardinalités observées, additionnelles et manquantes ;
- métriques preview ;
- état `safe-exact`, `explicit-generalization` ou `blocked` ;
- `autoApplicable`, codes raison et explication.

`autoApplicable` signifie uniquement que la représentation est mathématiquement exacte. Le resolver n'applique jamais le candidat.

### ExistingFortiObjectMatch

Le matching utilise uniquement :

- CIDR normalisé ;
- bornes d'une plage IP ;
- égalité de membership.

Le nom est conservé pour l'affichage futur, mais n'intervient ni dans le matching, ni dans le rang, ni dans l'identité du candidat. Plusieurs objets pour la même membership sont marqués ambigus et ne sont pas auto-sélectionnés.

### ExactGroupCandidate

Les groupes sont développés récursivement depuis `members`. Le cache legacy `expandedCidrs` n'est pas considéré comme une preuve. Le resolver détecte :

- groupes imbriqués ;
- cycles avec chemins déterministes ;
- membres absents/non représentables ;
- memberships contenant des adresses supplémentaires.

Un groupe existant n'est candidat que si son union finale est exactement égale aux hosts observés.

Un nouveau groupe exact propose :

1. la réutilisation des objets host `/32` existants ;
2. la création des seuls objets host manquants ;
3. une définition de groupe par références, sans imposer de nom ni produire de CLI.

### CIDRCandidate

Les CIDR proviennent de :

- objets FortiGate existants ;
- réseaux d'interfaces ;
- réseaux configurés explicitement dans les options ;
- minimal cover calculé depuis les IP observées.

Par défaut :

```text
maxCandidateAddresses = 4096
maxCidrCandidates = 20
```

Un CIDR expose densité, adresses additionnelles, tuples additionnels et expansion. Tous les `cidr-suggestion` ont `autoApplicable=false`, même lorsque leur membership est exacte. Un CIDR sparse est `explicit-generalization`.

### ResolutionResult

Le résultat contient :

- la représentation courante `host-list` ;
- les candidats triés par priorité et impact ;
- le candidat recommandé sûr ;
- un `resolverInputHash` et un `configFingerprint` ;
- les métriques par candidat ;
- les diagnostics de groupes ;
- la trace des FlowAtoms et du Traffic Scope si présents.

Les identifiants et sorties restent stables malgré l'ordre des arrays, objets de configuration et membres de groupes. Renommer un objet change le fingerprint de configuration — pour invalider une future décision — mais pas l'identité technique, le rang ou les métriques du candidat.

## Priorités

1. objet FortiGate exact ;
2. groupe FortiGate exact ;
3. nouveau groupe exact ;
4. CIDR en suggestion uniquement ;
5. hosts individuels, toujours disponibles.

Les ambiguïtés empêchent l'auto-sélection. Le repli `host-list` conserve toujours expansion et missing à zéro.

## Métriques preview

La policy V2 est interprétée selon sa sémantique réelle :

```text
sources × destinations × serviceKeys
```

Pour un candidat source :

```text
representedSources × destinations × serviceKeys
```

Pour un candidat destination :

```text
sources × representedDestinations × serviceKeys
```

Le resolver ne présente pas ses métriques preview comme un preflight final. Le workflow de décision Phase 4 reconstruit donc une copie de policy, appelle `evaluatePolicies()`, puis exécute l'analyse FortiGate et le preflight avant d'indiquer si une génération serait possible.

## Intégration backend Phase 3

La façade pure `app/web/lib/network-representation-integration.js` reçoit un résultat Policy Engine V2, une configuration FortiGate et un `policyId`. Elle :

1. retrouve uniquement une policy V2 portant `safeExact=true` ;
2. appelle le resolver séparément pour `source` et `destination` ;
3. valide les deux `ResolutionResult` ;
4. projette une réponse bornée sans les `representedIps` développées ;
5. ne modifie ni la policy ni les métriques du moteur.

Endpoint en lecture seule :

```text
GET /api/policy-engine/v2/representations
  ?session=<session>
  &profile=recommended
  &traffic_scope=<scope>
  &policy_id=P-00001
```

La réponse expose exclusivement :

- candidates source et destination ;
- représentation, origine et objets concernés ;
- métriques preview ;
- `reasonCodes` et explication ;
- `safetyState = { eligibility, autoApplicable }` ;
- hashes resolver/config/scope et diagnostics nécessaires à l'invalidation future.

Elle n'expose aucun `UserDecision`, `finalMetrics` ni policy modifiée. Elle n'appelle jamais `evaluatePolicies`, `analyzePolicies`, `preflightValidation` ou `generateConfig`.

Le `resolverInputHash` inclut la policy exacte, le côté résolu, la configuration technique, la version resolver et la clé Traffic Scope. Un changement de configuration ou de scope invalide donc les deux résolutions.

Smoke Phase 3 sur image candidate et cache réel copié :

```text
GET Policy Engine V2                 HTTP 200
GET representations P-00001          HTTP 200
Candidates source / destination      3 / 2
policy_id absent / inconnu            400 / 404
Policies avant/après identiques      oui
Métriques avant/après identiques     oui
Missing / Unexpected / Expansion     0 / 0 / 0 %
Champs décision/application exposés  0
```

## Workflow contrôlé Phase 4

Le module `app/web/lib/network-representation-decision.js` implémente le contrat `UserDecision` et l'application sur copie :

```text
candidat courant
→ validation resolverInputHash / config / scope / policy / version
→ création UserDecision
→ clone de la policy
→ application de la représentation au clone
→ evaluatePolicies sur l'ensemble des policies
→ refus si missing ou unexpected non nul
→ analyzePolicies
→ preflightValidation
→ generationEligible (booléen seulement)
```

Types applicables : objet exact, groupe existant exact, nouveau groupe exact, host-list et CIDR. Un CIDR n'est accepté que si son expansion recalculée est nulle ; les CIDR sparse sont rejetés avec les métriques de dérive.

Une décision stocke au minimum :

- policy/candidate/side/profile ;
- `resolverInputHash` ;
- policy et config fingerprints ;
- Traffic Scope key ;
- métriques attendues ;
- statut et horodatage.

Une décision invalidée ne peut jamais redevenir valide. Les décisions sont persistées dans le cache session et dans les exports/workspaces `.ffws`.

API :

```text
POST /api/policy-engine/v2/representations/decisions
GET  /api/policy-engine/v2/representations/decisions
```

Le POST exige `policyId`, `side`, `candidateId` et `resolverInputHash`, retourne la policy appliquée/analysée, les métriques recalculées, le preflight et `generationEligible`. Le GET relit puis revalide la décision contre le contexte courant ; une dérive la fait passer à `invalidated` avec ses raisons.

Le workflow ne persiste jamais une décision refusée pour hash périmé, candidat absent, ambiguïté ou expansion. Il ne modifie pas la policy source et n'appelle jamais `generateConfig`.

### Correction immutabilité du policy context

Le premier replay AVR a révélé que les policies non sélectionnées restaient des références originales. `analyzePolicies()` enrichissait alors `_multiDstSubnets[*].addrFound/addrName` en place. La correction clone désormais profondément **tout** `engineResult.policies` avant d'appliquer la décision, puis transmet uniquement ce contexte cloné à `evaluatePolicies`, `analyzePolicies` et `preflightValidation`.

Tests dédiés : plusieurs policies non sélectionnées avec arrays/objets privés imbriqués, comparaison SHA-256 + `deepEqual`, et deux décisions concurrentes sur le même contexte original.

Replay AVR après correction, commit `2b550456f35ca273706f9479ee5c4fa6db498cb3` :

```text
Policies / FlowAtoms                         17 / 104
Hash original après exact object            identique
Hash original après new exact group         identique
Hash original après deux décisions          identique
Coverage / Missing / Unexpected / Expansion 100 % / 0 / 0 / 0 %
CIDR sparse refusé                           422 / 230 unexpected
Hash périmé refusé                           409
```

Le finding immutabilité HIGH est clos. Le passage UI reste cependant bloqué par un manque d'évidence distinct : la configuration AVR réelle correspondante contient zéro groupe d'adresses et ne permet pas de tester `existing-group` sur télémétrie réelle.

Smoke end-to-end Phase 4 sur image candidate, session synthétique isolée et redémarrage réel du conteneur :

```text
POST décision objet exact               HTTP 201
GET décision persistée                  HTTP 200 / valid=true
Décision après redémarrage conteneur     HTTP 200 / accepted
Coverage / Missing / Unexpected          100 % / 0 / 0
Expansion                               0 %
Preflight                               ok
generationEligible                      true
POST CIDR sparse                        HTTP 422
Unexpected CIDR refusé                  254
Policy et métriques moteur modifiées    non
Appel generateConfig                    aucun
```

Le seul workspace réel encore présent localement contient 1 439 flows, mais aucune configuration FortiGate et aucun flow V2 déployable restaurable (`0` policy). Il ne permet donc pas une validation réelle du workflow décisionnel. Aucun chiffre réel n'est inventé ; la validation sur dataset réel + configuration reste un gate avant UI.

## Tests Phase 2

La suite dédiée couvre :

- objet CIDR exact et plage IP exacte ;
- matching indépendant des noms ;
- objets exacts ambigus ;
- groupes imbriqués exacts ;
- membre supplémentaire, cycle et membre absent ;
- nouveau groupe exact et réutilisation des hosts ;
- CIDR sparse mesuré et non auto-applicable ;
- limite des réseaux trop larges ;
- source et destination ;
- immutabilité, sérialisation et déterminisme ;
- validation runtime des contrats.

Validation représentative hors intégration sur 403 policies Recommandées :

```text
Résolutions source/destination     806
host-list                          806
new-exact-group                    312
existing-object                     29
cidr-suggestion                    108
Temps resolver total             405 ms
Policies d'entrée modifiées           0
Missing / Unexpected / Expansion   0 / 0 / 0 %
```

`autoApplicable` reste une propriété mathématique du candidat ; aucune des suggestions ci-dessus n'a été appliquée au moteur.

## Hors scope Phase 4

Non implémentés volontairement :

- appel à `generateConfig` depuis le workflow de décision ;
- génération automatique ;
- UI complète ;
- déploiement.
