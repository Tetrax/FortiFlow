# Choix d’adresse FortiGate

## Autorités et gate

- La télémétrie est autoritaire pour les IP réellement observées.
- La configuration FortiGate est autoritaire pour le hostname, le serial/devid lorsqu’il est présent, le VDOM, les interfaces/réseaux et les objets `firewall address`.
- Toute contradiction d’identité, de VDOM ou de réseau d’interface bloque avant mutation de session, analyse, preflight et génération avec le message exact :

```text
La télémétrie et la configuration FortiGate ne correspondent pas.
```

Une identité absente reste inconnue et n’est jamais inventée. Un cluster HA ou plusieurs équipements ne passent que si les membres et la sélection technique sont explicites. Plusieurs VDOM sans sélection sont refusés.

## Les trois choix dans le drawer Source/Destination

1. **Objet FortiGate existant** — les objets subnet qui contiennent toutes les IP observées sont affichés directement. Le choix par défaut suit le longest-prefix match : préfixe le plus long, puis nom stable. Le drawer affiche le CIDR, le nombre d’hôtes observés et le nombre d’IP non observées avant `Utiliser cet objet`.
2. **Créer un subnet** — proposé seulement lorsqu’aucun objet existant ne contient toutes les IP. Le CIDR minimal couvrant les IP est calculé sans énumérer le réseau ; le drawer affiche les hôtes observés et les IP non observées, puis demande `Confirmer`.
3. **Créer les hôtes /32** — proposé dans le même cas. Chaque IP observée reste exacte ; un objet `/32` existant est réutilisé et les hôtes manquants sont créés après confirmation.

Les noms ne servent jamais à prouver une inclusion réseau. Les objets FQDN, plages et groupes ne sont pas des preuves de containment dans ce parcours simplifié.

## Validation serveur

Le navigateur conserve le choix uniquement dans la policy en cours. Avant le preflight et la génération, le serveur revalide le CIDR, la couverture de chaque IP observée, l’objet FortiGate courant et la confirmation. Un objet supprimé, un CIDR qui exclut un hôte ou une confirmation absente est refusé ; aucune décision réseau n’est persistée.

Le choix d’adresse ne modifie ni les FlowAtoms, ni l’affinité service/interface/VDOM, ni les garde-fous CLI (`ALL`, services globaux, dérive de service et scopes mélangés). L’import d’un workspace accepte un ancien champ `networkDecisions` mais l’ignore en mémoire.

## Limites V1

Pas de scoring, ranking, candidats génériques, expansion implicite, création de groupes, nouvelle page ou section parallèle. Le moteur Policy Engine V2 reste responsable de la vérité des tuples ; ce drawer ne fait que choisir la représentation d’adresse confirmée pour la génération courante.
