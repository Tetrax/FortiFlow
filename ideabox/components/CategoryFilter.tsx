'use client'
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
  const selectClass =
    'flex-1 rounded-lg border border-[var(--border)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8] bg-[var(--bg-card)] text-[var(--text-primary)]'

  return (
    <div className="flex flex-col sm:flex-row gap-3">
      <select
        value={selectedCategory}
        onChange={(e) => onCategoryChange(e.target.value)}
        className={selectClass}
        aria-label="Filtrer par catégorie"
      >
        <option value="">Toutes les catégories</option>
        {categories.map((cat) => (
          <option key={cat.id} value={cat.id}>
            {cat.icon} {cat.name}
          </option>
        ))}
      </select>

      <select
        value={selectedStatus}
        onChange={(e) => onStatusChange(e.target.value)}
        className={selectClass}
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
