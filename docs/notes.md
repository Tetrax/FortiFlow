# FortiFlow — Notes Projet

## Concept
Application web d'analyse et de refactoring des policies FortiGate.
Objectif : importer un fichier de conf FortiGate, visualiser les flux, nettoyer et recréer les policies proprement.

---

## Fonctionnalités notées (2026-03-15)

### Import de configuration
- Injection d'un fichier de conf FortiGate (.conf)
- Le fichier sert à :
  - Créer les policies de firewall automatiquement
  - Mapper les interfaces (source/destination)

### Gestion des objets manquants
#### Adresses / Objets réseau
- Si un objet d'adresse est manquant lors de la création d'une policy :
  - Afficher un prompt pour associer un nom
  - Créer l'objet dans `config firewall address` avec le nom choisi

#### Services / Ports
- Si un port/service est manquant :
  - Afficher un prompt pour choisir un nom
  - Créer l'entrée dans `config system service custom` (ou `config firewall service custom`)
  - Permettre de définir le protocole + port(s)

### Mapping des interfaces
- L'import du fichier de conf permet de détecter et mapper automatiquement les interfaces (port1, port2, DMZ, WAN, LAN, etc.)
- Utiliser ce mapping pour pré-remplir source/destination interface dans les policies

---

## Stack envisagée
- À définir (app web → probablement React/Vue + backend Python/Node)

---

## TODO
- [ ] Parser le fichier de conf FortiGate (format texte structuré)
- [ ] Extraire : policies, adresses, services, interfaces, routes
- [ ] UI pour visualiser les flux (source → destination → service → action)
- [ ] Workflow de résolution des objets manquants
- [ ] Export de la conf reconstruite proprement
