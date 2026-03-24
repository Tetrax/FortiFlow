'use client'
import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import IdeaCard, { IdeaCardProps } from '@/components/IdeaCard'
import CategoryFilter from '@/components/CategoryFilter'
import { IdeaStatus } from '@prisma/client'

interface Category {
  id: string
  name: string
  icon: string
}

interface Idea extends Omit<IdeaCardProps, 'categoryName' | 'categoryIcon'> {
  category: { name: string; icon: string }
}

interface ApiResponse {
  ideas: Idea[]
  pagination: { total: number; pages: number; page: number }
}

export default function IdeesPage() {
  const [ideas, setIdeas] = useState<Idea[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedCategory, setSelectedCategory] = useState('')
  const [selectedStatus, setSelectedStatus] = useState('')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)

  useEffect(() => {
    fetch('/api/categories')
      .then((r) => r.json())
      .then((data: Category[]) => setCategories(data))
      .catch(() => console.error('Erreur chargement catégories'))
  }, [])

  const loadIdeas = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({ page: String(page), limit: '12' })
      if (selectedCategory) params.set('categoryId', selectedCategory)
      if (selectedStatus) params.set('status', selectedStatus)

      const res = await fetch(`/api/ideas?${params.toString()}`)
      if (!res.ok) throw new Error('Erreur serveur')

      const data = (await res.json()) as ApiResponse
      setIdeas(data.ideas)
      setTotalPages(data.pagination.pages)
      setTotal(data.pagination.total)
    } catch {
      setError('Impossible de charger les idées. Réessayez.')
    } finally {
      setLoading(false)
    }
  }, [page, selectedCategory, selectedStatus])

  useEffect(() => { void loadIdeas() }, [loadIdeas])

  function handleCategoryChange(id: string) { setSelectedCategory(id); setPage(1) }
  function handleStatusChange(status: string) { setSelectedStatus(status as IdeaStatus | ''); setPage(1) }

  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <header className="bg-[var(--bg-card)] border-b border-[var(--border)]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-center gap-2 text-sm text-[var(--text-secondary)] mb-2">
            <Link href="/" className="hover:opacity-80 transition-opacity flex items-center">
              <Image src="/logo-sns.svg" alt="SNS Security" width={60} height={32} className="h-5 w-auto" />
            </Link>
            <span>›</span>
            <span>Les idées</span>
          </div>
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-[var(--text-primary)]">💡 Les idées</h1>
              <p className="text-[var(--text-secondary)] mt-1">
                {total > 0 ? `${total} idée${total > 1 ? 's' : ''} soumise${total > 1 ? 's' : ''}` : 'Aucune idée pour le moment'}
              </p>
            </div>
            <Link
              href="/soumettre"
              className="inline-block bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-medium px-5 py-2.5 rounded-lg hover:opacity-90 transition-opacity text-sm"
            >
              + Soumettre une idée
            </Link>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <CategoryFilter
            categories={categories}
            selectedCategory={selectedCategory}
            selectedStatus={selectedStatus}
            onCategoryChange={handleCategoryChange}
            onStatusChange={handleStatusChange}
          />
        </div>

        {loading && (
          <div className="text-center py-16 text-[var(--text-secondary)]">
            <p className="animate-pulse text-lg">Chargement des idées…</p>
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-700/50 dark:text-red-400 rounded-lg p-4 text-sm mb-6">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            {ideas.length === 0 ? (
              <div className="text-center py-16 text-[var(--text-secondary)]">
                <p className="text-5xl mb-4">🔍</p>
                <p className="text-lg font-medium text-[var(--text-primary)]">Aucune idée ne correspond à vos filtres.</p>
                <p className="text-sm mt-2">Essayez de modifier les filtres ou soumettez la première idée !</p>
              </div>
            ) : (
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                {ideas.map((idea) => (
                  <IdeaCard
                    key={idea.id}
                    {...idea}
                    categoryName={idea.category.name}
                    categoryIcon={idea.category.icon}
                  />
                ))}
              </div>
            )}

            {totalPages > 1 && (
              <div className="flex justify-center items-center gap-3 mt-10">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="px-4 py-2 rounded-lg border border-[var(--border)] text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  ← Précédent
                </button>
                <span className="text-sm text-[var(--text-secondary)]">
                  Page {page} / {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="px-4 py-2 rounded-lg border border-[var(--border)] text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  Suivant →
                </button>
              </div>
            )}
          </>
        )}
      </main>

      {/* Disclaimer CSE — visible et bien identifié */}
      <footer className="border-t border-amber-300 bg-amber-50 dark:bg-amber-900/20 dark:border-amber-700/50">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-start gap-3 text-sm text-amber-800 dark:text-amber-300">
          <span className="text-xl shrink-0 mt-0.5">⚠️</span>
          <p>
            <strong>Information importante :</strong> Seules les idées retenues par le CSE sont affichées sur cette page.
            Si votre idée n'apparaît pas, c'est qu'elle n'a pas été validée pour publication — elle a néanmoins bien été reçue et examinée par notre équipe.
          </p>
        </div>
      </footer>
    </div>
  )
}
