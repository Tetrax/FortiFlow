# FortiFlow — Guide utilisateur

> **FortiFlow** est un outil d'analyse de logs réseau FortiGate / FortiAnalyzer.
> Il vous permet de visualiser les flux, de générer des suggestions de policies firewall et de produire des commandes CLI prêtes à déployer sur un FortiGate.

---

## Sommaire

1. [Accès à l'application](#1-accès-à-lapplication)
2. [Importer un fichier de logs](#2-importer-un-fichier-de-logs)
3. [Dashboard — vue d'ensemble](#3-dashboard--vue-densemble)
4. [Onglet Analyse](#4-onglet-analyse)
   - 4.1 [Flows](#41-flows)
   - 4.2 [Matrice](#42-matrice)
   - 4.3 [Groupes](#43-groupes)
   - 4.4 [Ports](#44-ports)
5. [Onglet Policies](#5-onglet-policies)
   - 5.1 [Policies brutes](#51-policies-brutes)
   - 5.2 [Policies consolidées](#52-policies-consolidées)
   - 5.3 [Flux refusés](#53-flux-refusés)
6. [Onglet Déploiement](#6-onglet-déploiement)
   - Étape 1 : Config
   - Étape 2 : Interfaces
   - Étape 3 : Policies
7. [Export et sauvegarde](#7-export-et-sauvegarde)
8. [Questions fréquentes](#8-questions-fréquentes)

---

## 1. Accès à l'application

Ouvrez votre navigateur et accédez à :

```
https://devval.com
```

Aucune installation ni identifiant n'est requis. Chaque session est indépendante et isolée en mémoire serveur (durée de vie : 2 heures).

---

## 2. Importer un fichier de logs

### Formats acceptés

| Format | Extension |
|--------|-----------|
| Syslog FortiGate (key=value) | `.log` `.txt` |
| FortiAnalyzer CSV | `.csv` |
| Excel | `.xlsx` `.xls` |
| Archive compressée | `.gz` `.zip` |

> **Taille maximale :** 300 Mo (streaming — le fichier n'est pas entièrement chargé en RAM).

### Comment faire

1. Sur l'écran d'accueil, **glissez-déposez** votre fichier dans la zone centrale
   — ou cliquez sur le bouton **« Parcourir »** pour ouvrir le sélecteur de fichiers.
2. Une barre de progression s'affiche en temps réel avec :
   - le pourcentage d'avancement
   - la vitesse de traitement (lignes/sec)
   - le temps restant estimé (ETA)
3. Une fois l'analyse terminée, vous arrivez automatiquement sur le **Dashboard**.

---

## 3. Dashboard — vue d'ensemble

Le Dashboard présente 9 cartes statistiques résumant le contenu du fichier importé :

| Carte | Description |
|-------|-------------|
| **Sessions totales** | Nombre total d'entrées dans le log |
| **Flux uniques** | Combinaisons src/dst/port/proto distinctes |
| **IPs sources** | Nombre d'adresses IP sources uniques |
| **IPs destinations** | Nombre d'adresses IP destinations uniques |
| **Hôtes RFC1918** | Machines en adressage privé détectées |
| **Sous-réseaux sources** | Blocs /24 sources identifiés |
| **Taux d'acceptation** | % de sessions avec action ACCEPT |
| **Sessions refusées** | Nombre de sessions DENY / DROP |
| **Volume total** | Quantité de données transférées (octets) |

Deux mini-cartes supplémentaires montrent la répartition **ACCEPT vs DENY** et la destination **LAN vs WAN**.

### Boutons disponibles

| Bouton | Action |
|--------|--------|
| **◎ Voir les policies** | Aller directement à l'onglet Policies |
| **+ Nouveau fichier** | Retourner à l'écran d'import pour analyser un autre fichier |

---

## 4. Onglet Analyse

### 4.1 Flows

Liste détaillée de tous les flux réseau extraits du log.

#### Filtres disponibles

| Champ | Description |
|-------|-------------|
| **IP source** | Filtre sur l'adresse IP source (partiel accepté) |
| **IP destination** | Filtre sur l'adresse IP destination |
| **Port** | Numéro de port destination |
| **Protocole** | TCP, UDP, ICMP, GRE |
| **Action** | accept, deny, drop |
| **Type destination** | LAN (RFC1918) ou WAN (Internet) |

Cliquez sur **« Filtrer »** pour appliquer, **« Reset »** pour tout effacer.

#### Tableau des flux

Les colonnes sont **cliquables** pour trier (↑ croissant, ↓ décroissant) :

| Colonne | Description |
|---------|-------------|
| **IP source** | Adresse IP source |
| **Sous-réseau src** | Bloc /24 de la source |
| **IP destination** | Adresse IP destination |
| **Type dst** | LAN ou WAN |
| **Port** | Port destination |
| **Proto** | Protocole réseau |
| **Service** | Nom du service si connu (HTTP, HTTPS…) |
| **Action** | ACCEPT (vert) / DENY (rouge) / DROP (rouge) |
| **Sessions** | Nombre d'occurrences agrégées |
| **Octets** | Volume de données |

La pagination affiche **100 lignes par page**. Naviguez avec les boutons **‹ Préc** / **Suiv ›** ou les numéros de page.

#### Export

Le bouton **⬇ CSV** (en haut à droite) télécharge les flux **filtrés** au format CSV.

---

### 4.2 Matrice

Carte de chaleur (heatmap) des communications inter-sous-réseaux (trafic privé uniquement).

- **Axe X** : sous-réseaux /24 destinations
- **Axe Y** : sous-réseaux /24 sources
- **Intensité de couleur** : volume de sessions (échelle logarithmique)

#### Basculer l'affichage

| Bouton | Affichage |
|--------|-----------|
| **✔ Acceptés** | Heatmap verte — flux autorisés |
| **✖ Refusés** | Heatmap rouge — flux bloqués |

#### Interactions

| Action | Résultat |
|--------|----------|
| **Survol d'une cellule** | Tooltip : source, destination, sessions, services, ports |
| **Clic sur une cellule** | Aller dans l'onglet Flows avec src/dst pré-filtrés |

La cellule diagonale (même sous-réseau) est mise en évidence différemment.

---

### 4.3 Groupes

Vue par sous-réseau source avec détail des destinations.

#### Cartes de sous-réseau

Chaque carte affiche :
- Le sous-réseau (ex. `192.168.1.0/24`)
- Nombre d'hôtes sources
- Nombre de destinations LAN et WAN
- Sessions totales

En développant une carte, vous voyez chaque destination avec :
- Type (LAN / WAN + drapeau pays pour les IPs publiques)
- Services détectés (8 premiers, puis « +X autres »)
- Sessions et octets

#### Panneau Hôtes

Cliquez sur le compteur d'hôtes d'une carte pour ouvrir le **panneau hôtes** :
- Liste des IPs individuelles du sous-réseau
- Pour chaque hôte : destinations, services, sessions
- Bouton **→ Flux** : filtre directement l'onglet Flows sur cet hôte

---

### 4.4 Ports

Visualisation des **25 ports TCP et 25 ports UDP** les plus utilisés.

Pour chaque port :
- Rang (1–25)
- Numéro de port
- Nom du service si connu
- Barre proportionnelle au volume de sessions
- Nombre de sessions et pourcentage du trafic total

---

## 5. Onglet Policies

### 5.1 Policies brutes

Suggestions de règles firewall générées automatiquement à partir des flux.

#### Filtre

Sélectionnez **Toutes / LAN uniquement / WAN uniquement** puis cliquez **« Filtrer »**.

#### Tableau

| Colonne | Description |
|---------|-------------|
| **#** | Numéro de ligne |
| **Source** | Sous-réseau /24 source |
| **Destination** | IP ou sous-réseau destination |
| **Services / Ports** | Services identifiés (max 10, puis « +X autres ») |
| **Sessions** | Nombre de sessions couvertes par cette règle |
| **Volume** | Octets transférés |
| **Action** | ACCEPT ou DENY |
| **Nom suggéré** | Nom de règle généré automatiquement |
| **▾ Hôtes** | Développer pour voir les paires src→dst individuelles |

#### Export

**⬇ Export CSV FortiGate** — télécharge les policies au format CSV.

---

### 5.2 Policies consolidées

Algorithme de consolidation en **2 passes** qui réduit le nombre de règles :
- **Passe 1** : regroupe les règles ayant la même destination et le même ensemble de services
- **Passe 2** : regroupe les règles ayant les mêmes sources et services

La bannière en haut indique le gain : **« X → Y règles · −Z% »**

#### Tableau consolidé

| Colonne | Description |
|---------|-------------|
| **#** | ID de policy |
| **Sources** | Une ou plusieurs sources (cliquer pour déplier la liste) |
| **Destinations** | Une ou plusieurs destinations avec type LAN/WAN |
| **Services / Ports** | Services couverts |
| **Sessions** | Volume agrégé |
| **Volume** | Octets agrégés |
| **Économies** | Badge « −X règles » ou « 1:1 » |
| **▾ Détail** | Développer pour voir le détail des règles fusionnées |

> **Conseil :** Utilisez cet onglet pour obtenir une configuration FortiGate compacte avant de passer au déploiement.

#### Export

**⬇ CSV consolidé** — format compatible FortiGate multi-src/dst.

---

### 5.3 Flux refusés

Liste des flux bloqués (DENY / DROP) groupés par paire de sous-réseaux.

| Colonne | Description |
|---------|-------------|
| **☐** | Case à cocher pour sélection |
| **Source** | Sous-réseau source |
| **Destination** | IP/sous-réseau destination |
| **Type** | LAN ou WAN |
| **Services / Ports** | Services bloqués |
| **Impact** | Barre proportionnelle au nombre de sessions |
| **Volume** | Octets |

Cochez les flux souhaités puis cliquez sur **« Envoyer X flux au déploiement »** pour les transférer automatiquement dans l'onglet Déploiement avec l'action `deny`.

---

## 6. Onglet Déploiement

Assistant en **3 étapes** pour générer des commandes CLI FortiGate.

---

### Étape 1 — Config

Importez votre fichier de configuration FortiGate existant (`.conf` ou `.txt`).

Une fois chargé, un résumé affiche :
- Adresses et groupes d'adresses existants
- Services et groupes de services
- Nombre de policies existantes
- Interfaces, zones, routes
- État SD-WAN, BGP, OSPF, VDOM

Le bouton **↺ Recharger** permet de recharger le fichier config.

---

### Étape 2 — Interfaces & Zones

Classez chaque interface en cliquant sur son bouton de type qui **bascule** entre :

```
LAN  →  WAN  →  VPN  →  LAN  → ...
```

Le tableau affiche pour chaque interface : nom, IP/CIDR, type, alias.

Les **zones** et leur composition sont affichées en dessous.

Si le **SD-WAN** est activé, une section supplémentaire permet de choisir l'interface/zone SD-WAN prioritaire pour les flux Internet (sélection par bouton radio).

Naviguez avec **← Précédent** / **Suivant →**.

---

### Étape 3 — Policies à déployer

#### Paramètres globaux

| Contrôle | Description |
|----------|-------------|
| **NAT** (checkbox) | Activer le NAT sur les policies WAN |
| **Action** (dropdown) | `accept` ou `deny` |
| **Log** (dropdown) | `all` / `utm` / `disable` |
| **Analyser les policies** | Lance la comparaison avec le fichier .conf importé |

#### Options de fusion (bouton ⚡ Fusion ▾)

| Option | Description |
|--------|-------------|
| **Fusionner Internet** | Regroupe tous les flux WAN en une seule règle |
| **Fusionner LAN** | Regroupe tous les flux LAN |
| **Tout fusionner** | Fusion maximale |
| **Par Policy ID** | Organisation par identifiant de policy source |
| **↺ Réinitialiser** | Repart des policies originales |

#### Options de vue (bouton ☰ Vue ▾)

| Option | Description |
|--------|-------------|
| **☰ Liste classique** | Tableau plat, toutes les policies |
| **⇄ Par interfaces** | Groupé par paire srcintf → dstintf |
| **⊞ Séquences** | Agrégé par src/dst/services identiques |

#### Granularité

| Bouton | Description |
|--------|-------------|
| **/24 ↔ /32** | Basculer entre sous-réseau (/24) et hôtes individuels (/32) |

#### Avertissements

Le bouton **⚠ …** apparaît si des adresses ou services référencés n'existent pas dans le fichier .conf. Cliquez pour voir la liste des objets manquants.

#### Tableau des policies

| Colonne | Description |
|---------|-------------|
| **☐** | Sélectionner la policy pour la génération |
| **Source** | Sous-réseau ou badge `[N hôtes]` (cliquable) |
| **Destination** | IP/sous-réseau ou `all (internet)` |
| **Services** | Description des services |
| **Sessions / Octets** | Statistiques issues du log |
| **NAT** | Checkbox individuelle par policy |
| **Interface In** | Interface source FortiGate |
| **Interface Out** | Interface destination FortiGate |
| **Action** | ACCEPT ou DENY |

#### Génération de la configuration CLI

1. Cochez les policies souhaitées (ou utilisez la case "tout sélectionner").
2. Cliquez sur **⬇ Générer config FortiGate**.
3. Un aperçu **CLI** s'affiche en bas de page (section « Aperçu CLI »).
4. Utilisez **📋 Copier** pour copier dans le presse-papier ou **⬇ Télécharger** pour sauvegarder un fichier `.conf`.

---

## 7. Export et sauvegarde

| Bouton | Emplacement | Description |
|--------|-------------|-------------|
| **⬇ CSV** (flows) | Analyse > Flows | Exporte les flux filtrés |
| **⬇ Export CSV FortiGate** | Policies > Brutes | Exporte les policies brutes |
| **⬇ CSV consolidé** | Policies > Consolidées | Exporte les policies consolidées |
| **⬇ Générer config** | Déploiement > Étape 3 | Génère le fichier CLI FortiGate |
| **📋 Copier** | Déploiement > Étape 3 | Copie la config CLI |
| **⬇ Télécharger** | Déploiement > Étape 3 | Télécharge la config CLI |
| **💾 Sauvegarder** | Déploiement > Étape 3 | Exporte la session complète (JSON) |
| **📂 Charger** | Déploiement > Étape 3 | Importe une session sauvegardée |

> **Note :** Les sessions expirent automatiquement après **2 heures** d'inactivité. Utilisez **💾 Sauvegarder** si vous souhaitez reprendre votre travail plus tard.

---

## 8. Questions fréquentes

**Q : Mon fichier est trop volumineux, que faire ?**
R : FortiFlow accepte jusqu'à 300 Mo et supporte les archives `.gz` / `.zip`. Compressez votre fichier avant l'import.

**Q : Les policies générées sont-elles directement applicables ?**
R : Oui, à condition d'avoir importé votre fichier `.conf` à l'étape 1 du déploiement. FortiFlow vérifie les objets existants et vous avertit des manquants (bouton ⚠).

**Q : Que signifie le taux d'acceptation affiché sur le Dashboard ?**
R : C'est le pourcentage de sessions avec l'action `ACCEPT` par rapport au total (`ACCEPT + DENY + DROP`).

**Q : La matrice n'affiche rien, c'est normal ?**
R : La matrice n'affiche que le trafic **privé → privé** (RFC1918). Si votre log ne contient que du trafic vers Internet, la matrice sera vide.

**Q : Comment reprendre une analyse le lendemain ?**
R : Depuis l'étape 3 du déploiement, utilisez **💾 Sauvegarder** pour exporter votre session. Rechargez-la le lendemain avec **📂 Charger** (la session serveur aura expiré, mais vos données locales seront intactes).

**Q : L'interface source/destination dans le tableau de déploiement est incorrecte.**
R : Retournez à l'**étape 2** et modifiez le type de l'interface concernée (LAN / WAN / VPN) via le bouton bascule.

---

*Document généré pour FortiFlow v1.0.0 — https://devval.com*
