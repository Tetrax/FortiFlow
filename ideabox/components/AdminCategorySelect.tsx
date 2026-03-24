'use client'
import type { Category } from '@/types'

interface AdminCategorySelectProps {
  categories: Category[]
  defaultValue: string
  statusFilter?: string
}

export default function AdminCategorySelect({
  categories,
  defaultValue,
  statusFilter,
}: AdminCategorySelectProps) {
  function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const p = new URLSearchParams()
    if (statusFilter) p.set('status', statusFilter)
    if (e.target.value) p.set('categoryId', e.target.value)
    window.location.href = `/admin/idees?${p.toString()}`
  }

  return (
    <select
      defaultValue={defaultValue}
      onChange={handleChange}
      className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8] bg-[var(--bg-card)] text-[var(--text-primary)]"
    >
      <option value="">Toutes les catégories</option>
      {categories.map((cat) => (
        <option key={cat.id} value={cat.id}>
          {cat.icon} {cat.name}
        </option>
      ))}
    </select>
  )
}
