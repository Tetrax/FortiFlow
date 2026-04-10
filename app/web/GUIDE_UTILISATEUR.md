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
7. [Workspaces — gestion des analyses](#7-workspaces--gestion-des-analyses)
8. [Export et sauvegarde](#8-export-et-sauvegarde)
9. [Page Admin](#9-page-admin)
10. [Questions fréquentes](#10-questions-fréquentes)

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

#### Export de la matrice

Deux boutons d'export sont disponibles en haut de la matrice :

| Bouton | Format | Description |
|--------|--------|-------------|
| **⬇ PNG** | Image | Capture la heatmap en PNG (nommée avec horodatage) |
| **⬇ Excel** | `.xlsx` | Exporte les données brutes de la matrice dans un tableur |

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

#### Support multi-VDOM

Si le fichier de configuration contient plusieurs **VDOM**, un sélecteur apparaît dans le résumé de configuration. Choisissez le VDOM cible dans la liste déroulante — FortiFlow rechargera automatiquement les interfaces, zones, adresses et policies du VDOM sélectionné pour l'ensemble du déploiement.

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

#### Barre de recherche

Un champ de recherche libre filtre les policies en temps réel. Syntaxes supportées :

| Syntaxe | Exemple | Effet |
|---------|---------|-------|
| Texte libre | `192.168.1` | Filtre par IP, subnet, service |
| `srcintf:NOM` | `srcintf:port1` | Filtre par interface source exacte |
| `dstintf:NOM` | `dstintf:wan1` | Filtre par interface destination exacte |

#### Modes de vue des policies

La toolbar contient un sélecteur pour basculer entre **deux modes de regroupement** des policies :

| Mode | Libellé | Affichage | Utilité |
|------|---------|-----------|---------|
| **Par paire d'interfaces** | **(sélection par défaut)** | Groupe les policies par paire (srcintf → dstintf). Chaque groupe affiche un en-tête avec le nombre de policies et un bouton **⚡ Fusionner** pour fusionner UNIQUEMENT ce groupe selon la stratégie active. Idéal pour affiner la fusion par domaine. | Travail granulaire : fusionner groupe par groupe |
| **Par séquence** | **(mode agrégé)** | Les policies sont agrégées en séquences (ensemble de policies avec les mêmes services). Affiche un badge **×N** pour indiquer le nombre de policies fusionnées. Vue compacte. | Visibilité globale et génération CLI plus rapide |

Basculez entre ces deux modes en cliquant sur les boutons dans la toolbar. Chaque mode conserve ses propres paramètres de fusion.

#### Menu ⚡ Fusion

Le menu **Fusion** combine un **périmètre** et une **stratégie** de regroupement pour les policies **de l'étape 3**.

**Périmètre :**

| Bouton | Effet |
|--------|-------|
| **Tout** | Fusionne l'ensemble des policies |
| **Internet** | Fusionne uniquement les policies WAN |
| **LAN** | Fusionne uniquement les policies LAN |

**Stratégie** (du plus granulaire au plus réducteur) :

| Stratégie | Granularité | Description |
|-----------|-------------|-------------|
| **Par service** | Le plus granulaire | Regroupe par même ensemble de services + interfaces → règles multi-sources ET multi-destinations. Idéal pour construire des policies propres depuis une config permissive. |
| **Par source** | Bon compromis | Regroupe par même flux src→dst → une règle par source. Bon équilibre entre granularité et volume. |
| **Par destination** | Réducteur | Regroupe par même destination + interfaces → fusionne les sources différentes en règles multi-sources. Réduit bien sans trop élargir les règles. |
| **Par interface** | Le plus réducteur | ⚠ Regroupe par policy d'origine. Peut recréer des règles très larges si la policy de départ était permissive (ex : any/any). |

**Actions de fusion :**

| Action | Description |
|--------|-------------|
| **▶ Appliquer** | Exécute la fusion globale selon le périmètre et la stratégie active. Un aperçu des modifications est proposé avant confirmation. |
| **⚡ Fusionner la sélection** | Fusionne uniquement les policies **cochées** dans le tableau (au lieu de toutes). Permet de cibler un sous-ensemble. |
| **⚡ Fusionner ce groupe** *(mode par paire d'interfaces)* | Bouton contextuel visible en mode **« Par paire d'interfaces »**. Lorsqu'une paire (srcintf → dstintf) contient plusieurs policies, ce bouton fusionne **uniquement ce groupe** selon la stratégie courante, sans affecter les autres paires. Très utile pour affiner progressivement. |
| **↺ Réinitialiser** | Repart des policies originales et annule toutes les fusions appliquées. |

#### Menu ☰ Vue *(options de vue)*

> Note : ce menu n'est pas intitulé « Vue » dans l'interface — les options de vue sont dans le même menu Fusion ou accessibles via d'autres contrôles. Se référer aux boutons disponibles dans la toolbar.

#### Bouton Détailler

Le bouton **Détailler ▾** cycle entre trois modes d'affichage des policies :

| Mode | Libellé | Description |
|------|---------|-------------|
| **off** | Détailler ▾ | Affichage consolidé par défaut |
| **service** | Par service ✓ | Éclate chaque policy en sous-policies par service |
| **host** | Par hôte 1:1 ✓ | Éclate chaque policy en paires source/destination individuelles |

#### Granularité /24 ↔ /32

| Bouton | Description |
|--------|-------------|
| **/24 ↔ /32** | Basculer entre sous-réseau (/24) et hôtes individuels (/32) |

#### Historique des modifications (Undo / Redo)

Deux boutons **‹** (annuler) et **›** (rétablir) permettent de naviguer dans l'historique des modifications de la liste de policies (jusqu'à 10 états). Le raccourci **Ctrl+Z** est également supporté depuis le panneau de détail d'une policy.

#### Flux sans réponse (scans potentiels)

FortiFlow détecte automatiquement les policies dont **≥ 80 % des flux n'ont reçu aucune réponse** (typique des scans réseau). Ces policies sont **masquées par défaut**.

Un bouton apparaît dans la toolbar pour les afficher/masquer, avec le nombre de policies concernées.

#### Objets manquants

Si des adresses ou services référencés n'existent pas dans le fichier `.conf`, une **barre d'avertissement** s'affiche en orange sous la toolbar. Cliquez dessus pour ouvrir la **modale de nommage des objets** :
- Liste de tous les objets à créer (adresses, hôtes, services)
- Champ de renommage pour chaque objet
- Les objets renommés seront utilisés dans la config CLI générée

#### Profils de sécurité

Après l'analyse des policies, si le fichier `.conf` contient des profils de sécurité, une barre apparaît au-dessus du bouton de génération avec des listes déroulantes :

| Sélecteur | Profil |
|-----------|--------|
| **AV** | Antivirus |
| **WebFilter** | Filtrage web |
| **IPS** | Système de prévention d'intrusion |
| **SSL/SSH** | Inspection SSL/SSH |

Les profils sélectionnés seront inclus dans la configuration CLI générée.

#### Avertissements

Le bouton **⚠ …** apparaît si des adresses ou services référencés n'existent pas dans le fichier .conf. Cliquez pour voir la liste des objets manquants.

#### Tableau des policies

| Colonne | Description |
|---------|-------------|
| **☐** | Sélectionner la policy pour la génération |
| **Source** | Sous-réseau ou badge `[N hôtes]` (cliquable) |
| **Destination** | IP/sous-réseau, `all (internet)`, ou **IPs spécifiques** (cliquable pour WAN multihost) |
| **Services** | Description des services |
| **Sessions / Octets** | Statistiques issues du log |
| **NAT** | Checkbox individuelle par policy |
| **Interface In** | Interface source FortiGate |
| **Interface Out** | Interface destination FortiGate |
| **Action** | ACCEPT ou DENY |

##### Comportement automatique des destinations WAN

Pour les policies WAN avec **plus de 10 hôtes ou sous-réseaux en destination**, le mode passe automatiquement en **"all"** au lieu de lister les IPs individuellement. Cette réduction rend les policies plus gérables.

L'utilisateur peut toujours cliquer sur **« IPs spécifiques »** dans la colonne Destination pour basculer et affiner manuellement les destinations si nécessaire.

#### Menu Analyse ▾

Le menu **Analyse ▾** dans la toolbar donne accès à deux fonctionnalités d'analyse de la configuration FortiGate importée :

| Option | Description |
|--------|-------------|
| **⚠ Risques** | Ouvre/ferme le panneau d'analyse de risques |
| **⚙ Ports à risque** | Configure la classification des ports à risque |

#### Panneau d'analyse de risques

Le panneau de risques (accessible via **Analyse ▾ → ⚠ Risques**) présente deux sections :

**1. Flux à risque** — Policies contenant des ports classifiés à risque :

| Niveau | Description |
|--------|-------------|
| **CRITIQUE** | Ports toujours dangereux (ex : Telnet, RDP exposé) |
| **ÉLEVÉ** | Ports à haut risque |
| **MOYEN** | Ports risqués selon le contexte (WAN vs LAN) |

Pour chaque flux à risque : subnet source, destination, ports concernés et nombre de sessions.

**2. Policies trop permissives** *(nécessite un fichier .conf chargé)* — Détecte les policies de votre FortiGate existant qui sont trop larges (any/any, plages trop ouvertes), groupées par direction :
- LAN → WAN
- WAN → LAN
- LAN → LAN

Chaque entrée indique la raison (ex : source ou destination `all`, service `ALL`).

#### Configuration des ports à risque

Via **Analyse ▾ → ⚙ Ports à risque**, une modale permet de personnaliser la classification :

| Catégorie | Comportement |
|-----------|-------------|
| **Toujours CRITIQUE** | Port classé CRITIQUE quelle que soit la destination |
| **Toujours ÉLEVÉ** | Port classé ÉLEVÉ quelle que soit la destination |
| **CRITIQUE si WAN, MOYEN si LAN** | Niveau adapté selon la nature de la destination |
| **ÉLEVÉ si WAN, MOYEN si LAN** | Niveau adapté selon la nature de la destination |

Vous pouvez ajouter, modifier ou supprimer des entrées, puis cliquer **💾 Sauvegarder et relancer** pour appliquer. Le bouton **↺ Réinitialiser** revient aux valeurs par défaut.

#### Génération de la configuration CLI

1. Cochez les policies souhaitées (ou utilisez la case "tout sélectionner").
2. Cliquez sur **⬇ Générer config FortiGate**.
3. Un aperçu **CLI** s'affiche en bas de page (section « Aperçu CLI »).
4. Utilisez **📋 Copier** pour copier dans le presse-papier ou **⬇ Télécharger** pour sauvegarder un fichier `.conf`.
5. Le bouton **⊕ Diff** (visible après génération) compare la config générée avec la config importée et met en évidence les policies nouvelles ou modifiées.

---

## 7. Workspaces — gestion des analyses

### Qu'est-ce qu'un workspace ?

Un **workspace** est une analyse sauvegardée nommée de votre choix. Après avoir importé et analysé un fichier, FortiFlow vous propose automatiquement de nommer ce workspace pour le retrouver facilement dans l'historique.

### Créer un workspace

1. Après l'**import d'un fichier**, une modale apparaît : **« 💾 Nommer ce workspace »**
2. Entrez un nom explicite (ex : **« Client XYZ — Audit VPN »**, **« Prod — Logs du 2026-04-10 »**)
3. Cliquez **« Sauvegarder »** pour l'ajouter à l'historique
4. Vous pouvez aussi cliquer **« Passer »** pour ignorer (l'analyse reste active dans la session, mais ne sera pas sauvegardée)

### Charger un workspace depuis l'historique

Sur l'**écran d'accueil** (quand aucune session n'est active), la section **Historique** en bas à gauche affiche tous vos workspaces sauvegardés :

- **Clic sur un workspace** → recharge immédiatement cette analyse avec tous les paramètres (flows, policies, config, etc.)
- **Bouton ×** → supprime le workspace de l'historique
- Chaque workspace affiche son **nom** et la date relative de création (« il y a 2h », « il y a 1j », etc.)

### Reprendre un workspace depuis un fichier

Vous pouvez aussi **exporter un workspace complet** en fichier (`.ffws` ou `.json`) et le **réimporter plus tard** :

1. Depuis le **Dashboard**, cliquez **💾 Sauvegarder workspace** → télécharge un fichier d'export
2. De retour sur l'écran d'accueil, **glissez-déposez ce fichier** (ou utilisez le bouton **« 💾 Reprendre un workspace »**) pour le recharger complètement

> **Note :** Les workspaces sauvegardés en serveur expirent après **2 heures d'inactivité**. Utilisez l'export fichier si vous devez reprendre votre travail le lendemain.

### Durée de vie d'une session

- **Session serveur** : 2 heures d'inactivité → données serveur supprimées automatiquement
- **Workspace sauvegardé** (historique) : conservé indéfiniment dans le serveur
- **Workspace exporté** (fichier) : persiste localement, reproductible à l'infini

---

## 8. Export et sauvegarde

| Bouton | Emplacement | Description |
|--------|-------------|-------------|
| **⬇ CSV** (flows) | Analyse > Flows | Exporte les flux filtrés |
| **⬇ PNG** | Analyse > Matrice | Capture la heatmap en image PNG |
| **⬇ Excel** | Analyse > Matrice | Exporte les données de la matrice en XLSX |
| **⬇ Export CSV FortiGate** | Policies > Brutes | Exporte les policies brutes |
| **⬇ CSV consolidé** | Policies > Consolidées | Exporte les policies consolidées |
| **📊 Export Excel** | Déploiement > Étape 3 | Exporte les policies de déploiement en XLSX |
| **📥 Import Excel** | Déploiement > Étape 3 | Réimporte les policies depuis un fichier XLSX modifié |
| **⬇ Générer config** | Déploiement > Étape 3 | Génère le fichier CLI FortiGate |
| **📋 Copier** | Déploiement > Étape 3 | Copie la config CLI |
| **⬇ Télécharger** | Déploiement > Étape 3 | Télécharge la config CLI |
| **💾 Sauvegarder workspace** | Dashboard | Exporte la session complète en fichier (`.ffws`) |

> **Note :** Les sessions expirent automatiquement après **2 heures** d'inactivité. Utilisez **💾 Sauvegarder workspace** si vous souhaitez reprendre votre travail plus tard (voir section [Workspaces](#7-workspaces--gestion-des-analyses)).

### Export / Import Excel des policies

Le couple **📊 Export Excel** / **📥 Import Excel** permet un flux de travail collaboratif :
1. Exportez les policies en XLSX depuis l'étape 3.
2. Modifiez les noms, actions ou commentaires dans le tableur.
3. Réimportez le fichier pour appliquer vos modifications dans FortiFlow.

---

## 9. Page Admin

FortiFlow expose une **page d'administration** pour surveiller et gérer les sessions actives (accès direct uniquement, pas de contrôle d'accès).

### Accès à la page Admin

```
https://devval.com/admin
```

### Fonctionnalités

La page affiche un **tableau en temps réel** de toutes les sessions serveur actives :

| Colonne | Description |
|---------|-------------|
| **Session ID** | Identifiant unique de la session (UUID) |
| **Statut** | `ready` (analyse terminée), `parsing` (en cours), `error` (erreur) |
| **Flows** | Nombre de flux uniques importés dans la session |
| **FortiConfig** | ✓ si un fichier `.conf` a été chargé, — sinon |
| **Créée** | Timestamp relatif de création (ex : « il y a 23 min ») |
| **Dernier accès** | Timestamp du dernier appel API de cette session |
| **Action** | Bouton ✕ pour supprimer manuellement une session |

### Outils

| Outil | Description |
|-------|-------------|
| **↻ Actualiser** | Recharge la liste des sessions (utile en mode manuel) |
| **Auto 5 s** | Checkbox — rafraîchit automatiquement le tableau tous les 5 secondes |
| **✕ Supprimer toutes** | Bouton dangereux — supprime TOUTES les sessions actives en une seule action |

### Cas d'usage

- **Monitoring** : vérifier quelles sessions sont actives et consomment de la RAM
- **Maintenance** : nettoyer les sessions orphelines ou "bloquées"
- **Debugging** : retrouver l'ID d'une session pour investigation

> **Note :** La page Admin n'a **aucun contrôle d'accès**. Elle suppose un accès réseau restreint (VPN, intranet fermé). À utiliser en environnement de confiance uniquement.

---

## 10. Questions fréquentes

**Q : Mon fichier est trop volumineux, que faire ?**
R : FortiFlow accepte jusqu'à 300 Mo et supporte les archives `.gz` / `.zip`. Compressez votre fichier avant l'import.

**Q : Les policies générées sont-elles directement applicables ?**
R : Oui, à condition d'avoir importé votre fichier `.conf` à l'étape 1 du déploiement. FortiFlow vérifie les objets existants et vous avertit des manquants (barre orange → cliquer pour nommer les objets).

**Q : Que signifie le taux d'acceptation affiché sur le Dashboard ?**
R : C'est le pourcentage de sessions avec l'action `ACCEPT` par rapport au total (`ACCEPT + DENY + DROP`).

**Q : La matrice n'affiche rien, c'est normal ?**
R : La matrice n'affiche que le trafic **privé → privé** (RFC1918). Si votre log ne contient que du trafic vers Internet, la matrice sera vide.

**Q : Comment reprendre une analyse le lendemain ?**
R : Utilisez **💾 Sauvegarder workspace** depuis le Dashboard pour exporter votre session en fichier (`.ffws`). Le lendemain, glissez-déposez ce fichier sur l'écran d'accueil ou cliquez **« 💾 Reprendre un workspace »** pour le recharger. La session serveur aura expiré, mais vos données persisteront dans le fichier. Voir [Workspaces](#7-workspaces--gestion-des-analyses).

**Q : L'interface source/destination dans le tableau de déploiement est incorrecte.**
R : Retournez à l'**étape 2** et modifiez le type de l'interface concernée (LAN / WAN / VPN) via le bouton bascule.

**Q : Que signifie le passage automatique à "all" pour les destinations WAN ?**
R : Quand une policy WAN dépasse 10 destinations, FortiFlow regroupe automatiquement en `all (internet)` pour lisibilité. Vous pouvez cliquer sur « IPs spécifiques » pour voir/modifier la liste détaillée.

**Q : Ma config FortiGate a plusieurs VDOM — comment choisir le bon ?**
R : Après l'import du fichier `.conf` à l'étape 1, un sélecteur de VDOM apparaît si plusieurs VDOM sont détectés. Choisissez le VDOM cible dans la liste — FortiFlow recharge automatiquement les données du VDOM sélectionné.

**Q : Certaines policies sont masquées par défaut — pourquoi ?**
R : FortiFlow masque les policies où ≥ 80 % des flux n'ont reçu aucune réponse réseau (scans potentiels). Cliquez sur le bouton "sans réponse" dans la toolbar pour les afficher.

**Q : Comment fonctionne l'analyse de risques ?**
R : Elle détecte deux types de problèmes : (1) des flux vers des ports dangereux dans votre log (Telnet, RDP exposé, etc.) et (2) des policies trop permissives dans votre config FortiGate existante (any/any, service ALL). La classification des ports est entièrement personnalisable via **Analyse ▾ → ⚙ Ports à risque**.

**Q : Quelle est la différence entre les stratégies de fusion ?**
R : "Par service" est la plus précise (une règle par groupe de services), "Par source" est un bon compromis, "Par destination" regroupe plusieurs sources vers un même endroit, "Par interface" est la plus agressive et peut créer des règles très larges. En cas de doute, commencez par "Par service".

**Q : Comment fusionner uniquement un groupe de policies ?**
R : En mode **« Par paire d'interfaces »** (dans la toolbar de l'étape 3), chaque groupe srcintf→dstintf affiche un bouton **⚡ Fusionner**. Cliquez pour fusionner UNIQUEMENT ce groupe selon la stratégie active, sans toucher aux autres paires. Idéal pour un contrôle granulaire.

**Q : À quoi sert le bouton "Fusionner la sélection" ?**
R : Il fusionne uniquement les policies que vous avez **cochées** dans le tableau (au lieu de toutes les policies). Cochez les policies concernées, puis utilisez ce bouton pour une fusion ciblée.

**Q : Quelle est la différence entre "Par paire d'interfaces" et "Par séquence" ?**
R : **Par paire** groupe les policies par (srcintf → dstintf), avec un bouton Fusionner par groupe — idéal pour affiner progressivement. **Par séquence** agrège les policies avec les mêmes services en une liste compacte — idéal pour une vue globale avant génération. Basculez entre les deux en cliquant les boutons de la toolbar (Étape 3).

**Q : Comment reprendre une analyse sauvegardée plus tard ?**
R : Deux options : (1) **Depuis l'historique serveur** : sur l'écran d'accueil, cliquez sur le workspace dans la section « Historique ». (2) **Depuis un fichier exporté** : glissez-déposez le fichier `.ffws` téléchargé précédemment sur l'écran d'accueil. Voir [Workspaces](#7-workspaces--gestion-des-analyses) pour plus de détails.

**Q : Où puis-je voir toutes les sessions actives en mémoire ?**
R : La page **/admin** affiche un tableau de toutes les sessions actives, avec des informations sur leur statut, le nombre de flows, la présence d'une config FortiGate, et les timestamps. Accès direct uniquement (pas de contrôle d'accès). Voir [Page Admin](#9-page-admin).

---

*Document généré pour FortiFlow v1.0.0 — https://devval.com*
