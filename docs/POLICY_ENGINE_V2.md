# Policy Engine V2

## Objectif

Policy Engine V2 transforme les flux déployables observés en policies FortiGate sans perdre l'affinité `(source, destination, service)`. Le profil **Recommandé** couvre exactement les permissions requises et n'en ajoute aucune. Toute généralisation est réservée à un profil explicite et accompagnée de métriques calculées.

## Audit du moteur initial

Le pipeline existant reste pertinent jusqu'à la normalisation de la télémétrie : parsing fail-closed, déduplication, isolation des scopes FortiGate/VDOM, conservation des tuples protocole/port/service, données temporelles, qualité de capture et preflight serveur.

La perte d'information apparaît ensuite :

1. `app/web/lib/analyzer.js` regroupe tôt les flux par réseau source et destination, puis accumule indépendamment les sources, destinations et services. Les ensembles aux lignes 153–171 ne conservent pas l'association hôte/hôte/service.
2. `app/web/public/segmentation-plan.js` reconstruit une union de services pour un ensemble de sources et destinations aux lignes 122–151. Le mode `grouped` représente ensuite cette union par une seule policy, donc par un produit cartésien implicite.
3. `app/web/public/app.js` `mergeByService` regroupe toutes les policies partageant un ensemble de services et une paire d'interfaces, puis prend l'union des sources et destinations (lignes 6244–6277). Le résultat n'est sûr que si le graphe source–destination est déjà complet.
4. `mergeByDestination` prend l'union des sources et des services pour une destination (lignes 6400–6430), ce qui peut créer des services non observés pour certaines sources.
5. L'agrégation réseau utilise des seuils de nombre d'hôtes (`hosts.length >= 5`, lignes 6291–6315 et 6443–6451) sans mesurer les hôtes potentiellement autorisés ni l'expansion.
6. Les profils `Large`, `Serveurs ciblés` et `Très précis` pilotent séparément granularité et services (lignes 7883–7912) ; l'optimizer reste une action avancée, alors qu'il doit être le moteur par défaut.

Les tests de caractérisation dans `app/web/test/current-policy-engine.characterization.test.js` figent les deux comportements dangereux sans les transformer en exigences V2.

## Modèle canonique

### FlowAtom

Un `FlowAtom` agrège uniquement des événements décrivant la même permission :

- scope FortiGate/VDOM ;
- source et destination IPv4 exactes ;
- protocole canonique et port destination ; pour ICMP, le couple type/code explicite porté par le log ;
- identité de service canonique ;
- interfaces/zones observées ;
- compteurs, première/dernière observation, jours distincts ;
- récurrence, confiance et raisons d'inéligibilité ;
- références stables vers les flux agrégés d'origine.

La clé de permission est déterminée par les dimensions qui changent réellement ce qu'une policy autorise. Le libellé FortiOS n'est jamais utilisé seul comme identité de service : la clé technique protocole/port reste autoritative.

### TrafficScope

Le `TrafficScope` filtre les flows **avant** `canonicalizeFlows()` ; aucun flow exclu ne devient donc un `FlowAtom`. Les modes backend sont `all`, `lan-lan`, `lan-internet`, `internet-lan`, `lan-dmz`, `dmz-lan` et `custom`.

La classification suit uniquement des preuves techniques, dans cet ordre : overrides DMZ explicites, `set role dmz`, interfaces/zones WAN, réseaux connectés configurés, adressage IPv4 privé/public, puis `unknown`. Les noms d'interfaces, zones et objets n'ont aucune sémantique. Le parseur conserve maintenant le rôle FortiGate des interfaces ; une zone n'hérite d'une classe que si tous ses membres sont connus et compatibles.

Le résultat expose séparément :

- `inputFlows` / `inputSessions` du dataset fourni ;
- `retainedFlows` / `retainedSessions` avant canonicalisation ;
- `excludedFlows` / `excludedSessions` hors scope ;
- `inputSummary`, qui continue de détailler l'éligibilité au déploiement dans le sous-ensemble retenu.

Le scope normalisé possède une clé déterministe incluse dans le cache du moteur et dans les métadonnées des policies. Le preflight reconstruit les atoms avec ce même scope et refuse une sélection mélangeant des scopes ou portant une clé altérée. L'API accepte `traffic_scope=<preset>` ou un objet JSON encodé dans ce paramètre ; un `custom` vide ou une classe inconnue est refusé.

### ServiceSignature

Pour un service canonique, sa signature comportementale est l'ensemble trié des arêtes `(source, destination)` observées dans un même scope et une même paire d'interfaces. Plusieurs services peuvent partager une policy uniquement si leurs signatures sont identiques.

## Safe merge déterministe

Le mode recommandé suit un algorithme borné :

1. normaliser et dédupliquer les `FlowAtom` ;
2. partitionner par scope et paire d'interfaces ;
3. construire, pour chaque service, le graphe biparti source → destination ;
4. regrouper les services ayant exactement le même ensemble d'arêtes ;
5. décomposer chaque graphe en rectangles complets sans arête ajoutée :
   - candidat orienté source : sources ayant exactement le même voisinage destination ;
   - candidat orienté destination : destinations ayant exactement le même voisinage source ;
   - retenir le candidat produisant le moins de policies, avec tie-break stable ;
6. appliquer une passe finale de fusion des sources uniquement entre policies ayant même partition, destinations et `serviceKeys`, puis prouver chaque tuple du rectangle candidat ;
7. réutiliser un objet source FortiGate existant seulement si son CIDR représente exactement toutes les sources de la policy, sans adresse supplémentaire ;
8. trier les membres, services et policies avec des clés canoniques ;
9. calculer les métriques depuis la sémantique cartésienne réelle de chaque policy ;
10. refuser le résultat recommandé si un tuple requis manque ou si un tuple inattendu apparaît.

Cette méthode n'essaie pas de résoudre une couverture minimale NP-difficile. Elle est déterministe, explicable, linéaire après tri par rapport au nombre de tuples canoniques, et conserve les intersections/résidus attendus.

## Invariants

Pour le profil recommandé :

```text
GeneratedAllowedTuples == ObservedRequiredTuples
MissingRequiredTuples = 0
UnexpectedAllowedTuples = 0
Coverage = 100 %
Expansion = 0 %
```

Autres invariants :

- aucune fusion entre équipements, VDOM ou paires d'interfaces incompatibles ;
- même entrée et même configuration donnent mêmes policies, ordre, noms, objets et métriques ;
- aucun repli vers `ALL`, `all` ou une plage dynamique ;
- aucun service prédéfini ou existant plus large que le tuple technique observé ;
- les alertes de qualité de capture et de certification restent visibles ;
- un résultat non prouvable échoue fermé.

## Métriques

Le moteur expose globalement et par policy :

- `observedRequiredTuples` ;
- `coveredRequiredTuples` ;
- `missingRequiredTuples` ;
- `allowedTuples` ;
- `unexpectedAllowedTuples` ;
- `coverageRatio` ;
- `expansionRatio` ;
- `blockedRequiredTuples` et `deployableRequiredTuples` afin de ne pas présenter un tuple non constructible comme déployable ;
- raison du regroupement et nombre d'atomes sources.

Le bloc `optimization` expose en plus :

- `before.policyCount` et toutes les métriques de sécurité avant la passe de sources ;
- `after.policyCount` et les mêmes métriques après optimisation ;
- `sourcePoliciesMerged` ;
- `sourceObjectsReused`.

Une policy est interprétée comme le produit cartésien `sources × destinations × services`. La matrice destination × service affichée par l'UI est dérivée des atomes justificateurs, pas de l'union de présentation.

### Agrégation sûre des sources

Le libellé affiché n'est jamais une identité de fusion : deux policies `DNS` basées respectivement sur `TCP:53` et `UDP:53` restent incompatibles. La passe de sources compare la partition complète, les destinations exactes et les `serviceKeys` techniques. Une fusion n'est appliquée qu'après vérification de chaque tuple source × destination × service dans les FlowAtoms.

Un objet CIDR existant est réutilisable en Recommandé uniquement lorsque sa cardinalité est égale au nombre de sources distinctes et que toutes les sources appartiennent à ce CIDR. Une simple inclusion ou densité ne suffit pas. Ainsi, 59 hôtes observés dans un `/23` de 512 adresses ne justifient jamais la réutilisation de cet objet avec expansion zéro.

## Agrégation réseau

- **Recommandé** : groupes d'hôtes exacts. Un objet réseau n'est utilisé sans expansion que si ses membres autorisables sont intégralement justifiés avec le même comportement.
- **Strict** : une policy par tuple canonique.
- **Synthétique** : peut proposer un réseau connu non chevauchant lorsque la densité et l'homogénéité dépassent les paramètres documentés. Les hôtes potentiels supplémentaires entrent dans `allowedTuples` et `unexpectedAllowedTuples`.
- **Expert** : expose les paramètres mesurables, jamais un seuil opaque du type « plus de N hôtes ».

Les objets existants sont préférés lorsqu'ils correspondent exactement aux membres ou au CIDR retenu. Une simple présence d'objet ne justifie jamais son périmètre.

## Normalisation des services

Chaque service est classé comme : prédéfini exact, objet existant exact, custom stable, port applicatif spécifique, rare, dynamique, candidat RPC, port destination illisible ou protocole non résolu. La priorité est : objet existant exact, prédéfini exact, custom exact et stable, objet custom dédié. Un objet ICMP type/code exact peut être réutilisé ; un libellé ICMP ne portant pas une preuve suffisante reste bloquant.

Les ports TCP élevés restent des tuples exacts en recommandé/strict. Une plage RPC dynamique ne peut être proposée qu'en synthétique/expert, avec détection explicite, expansion calculée et explication visible.

## Profils

| Profil | Intention | Expansion par défaut |
| --- | --- | --- |
| Recommandé | Rectangles sûrs, groupes d'hôtes exacts, résultat exploitable | 0 % |
| Strict | Une policy par tuple technique observé | 0 % |
| Synthétique | Réduction supplémentaire via généralisations justifiées | calculée et affichée |
| Expert | Paramètres effectifs du moteur exact et comparaison | 0 % tant qu'aucune généralisation explicite n'est activée |

## Intégration et traçabilité

Le moteur V2 est un module backend pur. L'API renvoie les policies, métriques, inventaire d'objets et explications. Le pipeline FortiGate existant continue d'analyser les objets, routes, zones et services puis exécute le preflight avant génération CLI. Après toute sélection utilisateur, le preflight recalcule coverage, missing et unexpected sur les FlowAtoms déployables complets ; une sélection incomplète ne peut plus être certifiée `exact`. Lors de la ré-analyse FortiGate, plusieurs tuples techniques portant le même libellé peuvent être représentés par un seul objet service exact ; le contrôle de dérive compare donc les ensembles de libellés uniques, tandis que le preflight technique reste autoritaire sur protocoles et ports.

Chaque policy conserve : identifiants d'atomes, membres exacts, signatures, motif de regroupement, services communs/résiduels, métriques et niveau de confiance. L'UI peut ainsi répondre « pourquoi ? » sans reconstruire artificiellement la preuve.

## Complexité algorithmique

L'agrégation initiale est une passe sur les flux. Les signatures utilisent des `Map`/`Set`, puis des tris canoniques. Aucun parcours des combinaisons possibles source × destination n'est effectué pour trouver les groupes ; seuls les tuples observés sont indexés. La matrice d'affinité construit une fois un index `service → destinations` au lieu de rescanner toutes les policies pour chaque cellule. Les expansions synthétiques sont comptées avec des cardinalités bornées et des échantillons limités.

## Validation mesurée

### Dataset réel préservé

Le dataset de référence reste hors Git et n'est jamais recopié dans la documentation. Résultat final du profil recommandé :

```text
Policies legacy                 1 793
Policies V2 recommended           388
Flow atoms                      7 230
Observed required tuples        7 230
Covered required tuples         7 230
Missing required tuples             0
Allowed tuples                  7 230
Unexpected allowed tuples           0
Coverage                       100 %
Expansion                        0 %
Blocked required tuples             7
Deployable required tuples      7 223
Temps moteur                  ~1,60 s
```

La correction ciblée ICMP rend 97 des 104 tuples initiaux constructibles en préservant les identités de services nommées et en réutilisant l'objet FortiGate `PING`. Les 7 tuples restants sont deux signatures ICMP sans type/code prouvable. Ils restent visibles, sont désélectionnés par défaut et rendent le preflight global `rejected` (`4` erreurs, `42` warnings). Le détail est dans `docs/ICMP_BLOCKER_ANALYSIS.md`.

### Performance

Pipeline streaming synthétique, résultat recommandé sans tuple manquant/inattendu :

| Événements | Flows canoniques | Parsing | Moteur | RSS observée |
| ---: | ---: | ---: | ---: | ---: |
| 100 000 | 50 000 | 736 ms | 531 ms | 274 MiB |
| 1 000 000 | 50 000 | 5 426 ms | 587 ms | 439 MiB |

Le profil strict sur le dataset réel produit 7 230 policies en environ 1,7 s. La réponse API tronque par défaut les listes d'atomes de traçabilité par policy à 100 entrées ; `include_trace=1` conserve la preuve complète à la demande.

Validation représentative de la phase Traffic Scope sur un cache réel local de 7 268 flows agrégés, profil Recommandé :

| Scope | Retenus | Exclus | Atomes | Policies | Missing | Unexpected | Expansion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| all | 7 268 | 0 | 7 021 | 403 | 0 | 0 | 0 % |
| LAN → LAN | 931 | 6 337 | 834 | 49 | 0 | 0 | 0 % |
| LAN → Internet | 5 875 | 1 393 | 5 755 | 302 | 0 | 0 | 0 % |
| Internet → LAN | 462 | 6 806 | 432 | 52 | 0 | 0 | 0 % |

Ces nombres qualifient le filtrage de phase 1 et ne remplacent pas le benchmark canonique ci-dessus. Les scopes DMZ dépendent de rôles FortiGate ou d'overrides explicites ; aucun nom n'est interprété.

Benchmark de régression de la matrice d'affinité, topologie clairsemée d'une source avec une destination et un service distincts par policy :

| Policies | Temps après indexation |
| ---: | ---: |
| 250 | 25 ms |
| 500 | 54 ms |
| 1 000 | 207 ms |

Avant correction, le cas 1 000 policies dépassait 5 secondes. L'endpoint est également placé derrière le rate limiter des routes coûteuses et met en cache le résultat par session, profil, Traffic Scope, flux et configuration.

## Review contradictoire DeepSeek

Une seule passe a été exécutée avec le provider DeepSeek ; Hermes a normalisé le modèle demandé vers `deepseek-v4-flash`. Verdict initial : **CONDITIONAL PASS**.

Traitement autonome des findings :

- **H1 ICMP** — validé et corrigé génériquement : type/code explicites et services ICMP nommés deviennent des clés distinctes, le parser conserve les champs ICMP et les objets exacts sont réutilisables. 97 tuples `PING` sont débloqués ; 7 restent honnêtement bloqués faute de preuve.
- **H2 objet réseau synthetic plus large** — hypothèse rejetée après lecture et test : `findAddress()` ne réutilise qu'un CIDR strictement égal ; un `/29` existant n'est pas réutilisé pour un `/30` mesuré.
- **M1 port destination illisible** — validé et corrigé : classification `unresolved-port`, blocker `MISSING_DSTPORT`, compteur de tuples bloqués.
- **M2 fusions legacy visibles** — validé et corrigé : bouton de groupe, colonne de sélection et fusion manuelle legacy retirés du DOM V2.
- **M3 généralisation manuelle dans le drawer** — validé et corrigé : les contrôles structurels V2 sont verrouillés ; un changement de profil déclenche un recalcul complet.
- **M4 taille API** — risque accepté et borné partiellement : trace atomique tronquée par défaut, preuve complète opt-in ; matrices UI limitées à 20 destinations × 30 services.
- **L1/L2/L3** — nettoyés ou explicités : profil initial V2 cohérent, métriques estampillées résultat initial, réponse API `Cache-Control: no-store`.

## Limitations restantes

- Les 7 tuples ICMP dont le log ne prouve pas un type/code ou un objet exact ne sont jamais élargis silencieusement vers `ALL_ICMP`.
- Le nombre de 388 policies reste supérieur à la cible indicative d'environ 60, mais il est obtenu sans overfitting et sans permission supplémentaire. Une réduction supplémentaire nécessite une généralisation réseau explicitement mesurée.
- L'UI a été validée dans Chromium headless sur un parcours réel API → analyse → Déployer → drawer. La validation humaine sur le navigateur de travail reste utile avant une release générale.
