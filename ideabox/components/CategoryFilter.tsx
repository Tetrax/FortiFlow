'use client'
// Filtres par catégorie et statut pour le mur des idées
import { IdeaStatus } from '@prisma/client'

interface Category {
  id: string
  name: string
  icon: string
}

interface CategoryFilterProps {
  categories: Category[]
  selectedCategory: string
  selectedStatus: string
  onCategoryChange: (id: string) => void
  onStatusChange: (status: string) => void
}

// Libellés des statuts
const STATUS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: '', label: 'Tous les statuts' },
  { value: IdeaStatus.NEW, label: '🆕 Nouvelle' },
  { value: IdeaStatus.REVIEWING, label: '🔍 En examen' },
  { value: IdeaStatus.ACCEPTED, label: '✅ Acceptée' },
  { value: IdeaStatus.REJECTED, label: '❌ Refusée' },
  { value: IdeaStatus.DONE, label: '🎉 Réalisée' },
]

export default function CategoryFilter({
  categories,
  selectedCategory,
  selectedStatus,
  onCategoryChange,
  onStatusChange,
}: CategoryFilterProps) {
  return (
    <div className="flex flex-col sm:flex-row gap-3">
      {/* Filtre catégorie */}
      <select
        value={selectedCategory}
        onChange={(e) => onCategoryChange(e.target.value)}
        className="flex-1 rounded-lg border border-[#1F2937] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8] bg-[#111111] text-white"
        aria-label="Filtrer par catégorie"
      >
        <option value="">Toutes les catégories</option>
        {categories.map((cat) => (
          <option key={cat.id} value={cat.id}>
            {cat.icon} {cat.name}
          </option>
        ))}
      </select>

      {/* Filtre statut */}
      <select
        value={selectedStatus}
        onChange={(e) => onStatusChange(e.target.value)}
        className="flex-1 rounded-lg border border-[#1F2937] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8] bg-[#111111] text-white"
        aria-label="Filtrer par statut"
      >
        {STATUS_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  )
}
