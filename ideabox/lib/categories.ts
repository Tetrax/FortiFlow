// Catégories par défaut pour la boîte à idées CSE

export interface DefaultCategory {
  name: string
  icon: string
}

export const DEFAULT_CATEGORIES: DefaultCategory[] = [
  { name: 'Organisation & RH', icon: '🏢' },
  { name: 'Conditions de travail', icon: '💼' },
  { name: 'RSE & Développement durable', icon: '🌿' },
  { name: "Vie d'entreprise & CSE", icon: '🎉' },
  { name: 'Outils & Digital', icon: '💻' },
  { name: 'Santé & Bien-être', icon: '🏥' },
  { name: 'Communication interne', icon: '📣' },
  { name: 'Autre', icon: '💡' },
]
