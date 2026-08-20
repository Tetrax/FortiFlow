# Analyse ciblée du blocker ICMP

## Périmètre

Cette analyse porte uniquement sur les 104 FlowAtoms ICMP initialement bloqués dans le dataset réel de référence. Les adresses exactes, objets et timestamps sont conservés dans un inventaire privé hors Git et hors Obsidian.

Tous les événements ICMP observés proviennent du même équipement/VDOM, de la même journée active et d'une policy existante permissive. Le fichier FAZ atteint exactement 100 000 lignes ; la complétude de la capture reste donc conditionnelle.

## Inventaire initial

| Service observé | Tuples | Sessions | Sources | Destinations | Information ICMP disponible |
| --- | ---: | ---: | ---: | ---: | --- |
| `PING` | 97 | 1 721 | 6 | 58 | nom de service ; la configuration sélectionnée définit `PING` comme ICMP type 8, code non contraint |
| `ICMP/0/8` | 5 | 74 | 3 | 5 | deux valeurs encodées dans le libellé, sans champs ICMP type/code conservés dans le cache |
| `GOOGLE-ICMP` | 2 | 136 | 1 | 2 | nom de service absent de l'inventaire FortiGate sélectionné ; aucun type/code conservé |

Justifications métier possibles, non certifiées :

- la majorité des `PING` part de serveurs de supervision vers des réseaux d'administration, serveurs, téléphonie, sauvegarde et industrie : contrôle de reachability inter-site probable ;
- quelques `PING` ponctuels partent de stations vers des destinations publiques : diagnostic ou contrôle de connectivité possible ;
- `GOOGLE-ICMP` relie un équipement Ewon à des préfixes Google : keepalive/connectivité industrielle probable ;
- `ICMP/0/8` inclut de la supervision vers des cibles internes et des événements ponctuels vers des préfixes Microsoft : sonde de reachability ou contrôle applicatif/OS possible.

Ces hypothèses ne remplacent pas la validation métier. Chaque famille n'est présente que sur un jour actif.

## Cause racine

Le blocker n'est pas une limitation de FortiGate : FortiOS sait représenter des objets ICMP avec type/code et fournit notamment un objet `PING`.

Il provenait de quatre limites d'implémentation/modèle :

1. les services ICMP sans port étaient tous ramenés à la même clé `ICMP` ; `PING` et `GOOGLE-ICMP` pouvaient donc perdre leur identité distincte ;
2. la résolution d'objet existant ne savait réutiliser que TCP/UDP ou un label `ICMP/type/code` explicite ;
3. `analyzePolicies()` appliquait un raisonnement par ports aux objets ICMP nommés ;
4. le parser/cache ne conservait pas les champs `icmptype` et `icmpcode`, même lorsqu'un export futur pourrait les fournir.

Le dataset conservé ne contient ni paquet brut, ni `icmptype`, ni `icmpcode`, ni fichier source original encore présent sur le VPS. Les valeurs absentes ne peuvent donc pas être reconstruites honnêtement.

## Correction générique

La correction minimale appliquée est indépendante du dataset :

- une identité ICMP nommée devient `ICMP:NAME:<service>` ;
- deux noms ICMP distincts ne sont plus fusionnés ;
- un nom ICMP est réutilisable uniquement si la configuration FortiGate sélectionnée contient exactement le même objet de protocole ICMP et si les type/code observés, lorsqu'ils sont disponibles, correspondent exactement ;
- un type/code explicite reste une clé technique séparée ;
- le parser conserve désormais `icmptype` et `icmpcode` et les ajoute à la clé d'agrégation ;
- le preflight compare la même clé technique ;
- aucun fallback `ALL_ICMP` n'est ajouté.

Cette correction rend les 97 tuples `PING` constructibles avec l'objet FortiGate `PING` existant. Elle ne crée aucune permission supplémentaire au niveau de l'identité de service observée et ne change pas les autres profils.

## Résultat après correction

```text
Observed required tuples        7 230
Covered required tuples         7 230
Missing required tuples             0
Unexpected allowed tuples           0
Expansion                            0 %
Blocked required tuples              7
Deployable required tuples       7 223
```

Le preflight complet reste volontairement rejeté :

```text
4 erreurs
42 warnings
certification: rejected
```

Après retrait automatique des quatre policies encore bloquées :

```text
384 policies
0 erreur
41 warnings
certification: conditional
```

La certification reste conditionnelle en raison de la qualité/complétude de capture, notamment le plafond FAZ possible et une seule journée ICMP active.

## Pourquoi 7 tuples restent bloqués

### `ICMP/0/8` — 5 tuples

Le cache ne permet pas de prouver si les deux valeurs représentent `(type, code)`, `(code, type)` ou une convention FortiOS différente. Interpréter automatiquement `0/8` comme echo request constituerait une hypothèse non prouvée. Aucun objet exact type/code correspondant n'est disponible dans la configuration sélectionnée.

Correction admissible future : réimporter le fichier source avec les nouveaux champs `icmptype`/`icmpcode`, obtenir une capture brute, ou fournir une documentation Fortinet autoritative sur l'ordre du libellé. Aucune table spéciale pour ce dataset ne doit être créée.

### `GOOGLE-ICMP` — 2 tuples

La configuration sélectionnée ne contient aucun objet ICMP nommé `GOOGLE-ICMP`, et le cache ne conserve aucun type/code. Le nom et les destinations Google suggèrent un contrôle de connectivité, mais ne définissent pas une permission FortiGate exacte.

Correction admissible future : obtenir la définition FortiGate originale de `GOOGLE-ICMP` ou les en-têtes ICMP bruts. Créer arbitrairement `PING` ou `ALL_ICMP` serait une expansion non mesurée.

## Verdict

La correction générique est pertinente et validée, mais elle ne justifie pas une acceptance complète : 97/104 tuples sont débloqués ; 7/104 doivent rester bloqués jusqu'à disponibilité d'une preuve type/code ou d'un objet FortiGate exact.
