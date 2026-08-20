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
6. trier les membres, services et policies avec des clés canoniques ;
7. calculer les métriques depuis la sémantique cartésienne réelle de chaque policy ;
8. refuser le résultat recommandé si un tuple requis manque ou si un tuple inattendu apparaît.

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

Une policy est interprétée comme le produit cartésien `sources × destinations × services`. La matrice destination × service affichée par l'UI est dérivée des atomes justificateurs, pas de l'union de présentation.

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

Le moteur V2 est un module backend pur. L'API renvoie les policies, métriques, inventaire d'objets et explications. Le pipeline FortiGate existant continue d'analyser les objets, routes, zones et services puis exécute le preflight avant génération CLI.

Chaque policy conserve : identifiants d'atomes, membres exacts, signatures, motif de regroupement, services communs/résiduels, métriques et niveau de confiance. L'UI peut ainsi répondre « pourquoi ? » sans reconstruire artificiellement la preuve.

## Complexité algorithmique

L'agrégation initiale est une passe sur les flux. Les signatures utilisent des `Map`/`Set`, puis des tris canoniques. Aucun parcours des combinaisons possibles source × destination n'est effectué pour trouver les groupes ; seuls les tuples observés sont indexés. Les expansions synthétiques sont comptées avec des cardinalités bornées et des échantillons limités.

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
Blocked required tuples           104
Deployable required tuples      7 126
Temps moteur                  ~1,60 s
```

Les 104 tuples bloqués sont deux signatures ICMP non résolues avec assez de précision pour produire automatiquement un objet FortiGate. Ils restent visibles, sont désélectionnés par défaut et rendent le preflight global `rejected` (`17` erreurs, `42` warnings). Le runtime principal ne peut donc pas être remplacé sur la base de ce dataset sans résolution ou acceptation explicite de cette limite.

### Performance

Pipeline streaming synthétique, résultat recommandé sans tuple manquant/inattendu :

| Événements | Flows canoniques | Parsing | Moteur | RSS observée |
| ---: | ---: | ---: | ---: | ---: |
| 100 000 | 50 000 | 736 ms | 531 ms | 274 MiB |
| 1 000 000 | 50 000 | 5 426 ms | 587 ms | 439 MiB |

Le profil strict sur le dataset réel produit 7 230 policies en environ 1,7 s. La réponse API tronque par défaut les listes d'atomes de traçabilité par policy à 100 entrées ; `include_trace=1` conserve la preuve complète à la demande.

## Review contradictoire DeepSeek

Une seule passe a été exécutée avec le provider DeepSeek ; Hermes a normalisé le modèle demandé vers `deepseek-v4-flash`. Verdict initial : **CONDITIONAL PASS**.

Traitement autonome des findings :

- **H1 ICMP** — validé partiellement et corrigé : type/code explicites deviennent une clé distincte, un objet ICMP exact peut être réutilisé, et les signatures non constructibles restent bloquées et comptées séparément. La limite réelle de 104 tuples demeure honnêtement visible.
- **H2 objet réseau synthetic plus large** — hypothèse rejetée après lecture et test : `findAddress()` ne réutilise qu'un CIDR strictement égal ; un `/29` existant n'est pas réutilisé pour un `/30` mesuré.
- **M1 port destination illisible** — validé et corrigé : classification `unresolved-port`, blocker `MISSING_DSTPORT`, compteur de tuples bloqués.
- **M2 fusions legacy visibles** — validé et corrigé : bouton de groupe, colonne de sélection et fusion manuelle legacy retirés du DOM V2.
- **M3 généralisation manuelle dans le drawer** — validé et corrigé : les contrôles structurels V2 sont verrouillés ; un changement de profil déclenche un recalcul complet.
- **M4 taille API** — risque accepté et borné partiellement : trace atomique tronquée par défaut, preuve complète opt-in ; matrices UI limitées à 20 destinations × 30 services.
- **L1/L2/L3** — nettoyés ou explicités : profil initial V2 cohérent, métriques estampillées résultat initial, réponse API `Cache-Control: no-store`.

## Limitations restantes

- Les services ICMP dont le log ne prouve pas un type/code exploitable ne sont jamais élargis silencieusement vers `ALL_ICMP`.
- Le nombre de 388 policies reste supérieur à la cible indicative d'environ 60, mais il est obtenu sans overfitting et sans permission supplémentaire. Une réduction supplémentaire nécessite une généralisation réseau explicitement mesurée.
- L'UI a été validée dans Chromium headless sur un parcours réel API → analyse → Déployer → drawer. La validation humaine sur le navigateur de travail reste utile avant une release générale.
