# 💡 SNSBox — Boîte à Idées CSE

Application web pour recueillir, gérer et suivre les idées des employés via le Comité Social et Économique (CSE).

## Stack technique

- **Next.js** (App Router, TypeScript)
- **Prisma 5** + **PostgreSQL** (compatible Supabase)
- **Tailwind CSS** — design mobile-first
- **NextAuth.js v5** — authentification admin
- **Resend** — emails transactionnels (stub si pas de clé)
- **Zod** — validation des données

---

## Prérequis

- Node.js 18+
- PostgreSQL (local ou Supabase)
- npm

---

## Installation

### 1. Cloner et installer les dépendances

```bash
cd snsbox
npm install
```

### 2. Configurer l'environnement

```bash
cp .env.example .env
```

Remplir `.env` :

```env
DATABASE_URL="postgresql://user:password@localhost:5432/snsbox"
NEXTAUTH_SECRET="votre-secret-32-chars-min"
NEXTAUTH_URL="http://localhost:3000"
RESEND_API_KEY=""          # optionnel
FROM_EMAIL="noreply@..."   # optionnel
NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

> 💡 Générer un secret : `openssl rand -base64 32`

### 3. Initialiser la base de données

```bash
# Créer les tables
npx prisma migrate dev --name init

# Insérer les données de démo
npm run seed
```

### 4. Lancer le serveur de développement

```bash
npm run dev
```

→ Ouvrir [http://localhost:3000](http://localhost:3000)

---

## Compte administrateur de démo

| Champ | Valeur |
|-------|--------|
| URL | `/admin/login` |
| Email | `admin@snsbox.fr` |
| Mot de passe | `Admin1234!` |

> ⚠️ Changer le mot de passe en production !

---

## Structure du projet

```
snsbox/
├── app/
│   ├── page.tsx                    # Accueil public
│   ├── idees/
│   │   ├── page.tsx                # Mur des idées
│   │   └── [id]/page.tsx           # Détail idée
│   ├── soumettre/page.tsx          # Formulaire soumission
│   ├── rgpd/page.tsx               # Page RGPD
│   ├── admin/
│   │   ├── login/page.tsx          # Connexion admin
│   │   ├── page.tsx                # Dashboard
│   │   └── idees/
│   │       ├── page.tsx            # Liste idées
│   │       └── [id]/page.tsx       # Gestion idée
│   └── api/
│       ├── ideas/route.ts          # GET liste + POST soumettre
│       ├── ideas/[id]/route.ts     # GET détail
│       ├── ideas/[id]/vote/route.ts # POST voter
│       ├── admin/ideas/[id]/route.ts # PATCH (protégé)
│       ├── categories/route.ts     # GET catégories
│       └── auth/[...nextauth]/route.ts
├── components/
│   ├── IdeaCard.tsx
│   ├── IdeaForm.tsx
│   ├── StatusBadge.tsx
│   ├── CategoryFilter.tsx
│   ├── VoteButton.tsx
│   └── AdminLayout.tsx
├── lib/
│   ├── prisma.ts                   # Singleton Prisma
│   ├── auth.ts                     # Config NextAuth
│   ├── email.ts                    # Resend (stub si pas de clé)
│   ├── votes.ts                    # Génération token de vote
│   └── categories.ts               # Catégories par défaut
├── prisma/
│   ├── schema.prisma               # Schéma de base de données
│   └── seed.ts                     # Données initiales
└── types/
    └── next-auth.d.ts              # Extensions de types
```

---

## Fonctionnalités

### Espace public

- **Accueil** : présentation et appels à l'action
- **Mur des idées** : liste avec filtres catégorie/statut, pagination
- **Détail idée** : description complète, badge de statut, réponse du CSE, vote
- **Formulaire** : soumission anonyme ou nominative, validation
- **RGPD** : politique de confidentialité complète

### Espace admin (`/admin`)

- **Connexion** sécurisée (email + mot de passe hashé bcrypt)
- **Dashboard** : compteurs par statut, idées récentes
- **Gestion des idées** : liste filtrée, modification statut, rédaction de réponse officielle, masquage

### Système de vote

- 1 vote par personne par idée par jour
- Token anonymisé : hash(IP + UserAgent + date) — sans cookie, sans login

---

## Déploiement

### Supabase (recommandé)

1. Créer un projet sur [supabase.com](https://supabase.com)
2. Copier la `DATABASE_URL` (onglet Settings > Database)
3. Lancer `npx prisma migrate deploy` pour appliquer les migrations
4. `npm run seed` pour les données initiales

### Vercel

```bash
# Variables d'environnement à configurer dans Vercel :
# DATABASE_URL, NEXTAUTH_SECRET, NEXTAUTH_URL, RESEND_API_KEY
vercel deploy
```

---

## Statuts des idées

| Statut | Couleur | Signification |
|--------|---------|---------------|
| `NEW` | Gris | Nouvelle idée, en attente d'examen |
| `REVIEWING` | Jaune | En cours d'étude par le CSE |
| `ACCEPTED` | Vert | Idée retenue, sera mise en œuvre |
| `REJECTED` | Rouge | Idée refusée (avec explication) |
| `DONE` | Bleu | Idée réalisée |

---

## Scripts disponibles

```bash
npm run dev          # Serveur de développement
npm run build        # Build de production
npm run start        # Serveur de production
npm run seed         # Insérer les données initiales
npx prisma studio    # Interface graphique base de données
npx prisma migrate dev  # Créer une migration
```

---

## RGPD

- Soumission anonyme par défaut
- Les adresses email ne sont jamais affichées publiquement
- Les tokens de vote sont des hashs non réversibles
- Voir `/rgpd` pour la politique complète
