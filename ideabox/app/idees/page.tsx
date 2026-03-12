'use client'
// Mur des idées avec filtres catégorie/statut
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

  // Charger les catégories au montage
  useEffect(() => {
    fetch('/api/categories')
      .then((r) => r.json())
      .then((data: Category[]) => setCategories(data))
      .catch(() => console.error('Erreur chargement catégories'))
  }, [])

  // Charger les idées selon les filtres
  const loadIdeas = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({
        page: String(page),
        limit: '12',
      })
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

  useEffect(() => {
    void loadIdeas()
  }, [loadIdeas])

  // Réinitialiser la page lors d'un changement de filtre
  function handleCategoryChange(id: string) {
    setSelectedCategory(id)
    setPage(1)
  }

  function handleStatusChange(status: string) {
    setSelectedStatus(status as IdeaStatus | '')
    setPage(1)
  }

  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* En-tête */}
      <header className="bg-[#111111] border-b border-[#1F2937]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-center gap-2 text-sm text-[#9CA3AF] mb-2">
            <Link href="/" className="hover:text-[#6B21E8] transition-colors flex items-center">
              <Image src="/logo-sns.svg" alt="SNS Security" width={60} height={32} className="h-5 w-auto" />
            </Link>
            <span>›</span>
            <span>Les idées</span>
          </div>
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-white">💡 Les idées</h1>
              <p className="text-[#9CA3AF] mt-1">
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
        {/* Filtres */}
        <div className="mb-8">
          <CategoryFilter
            categories={categories}
            selectedCategory={selectedCategory}
            selectedStatus={selectedStatus}
            onCategoryChange={handleCategoryChange}
            onStatusChange={handleStatusChange}
          />
        </div>

        {/* États de chargement / erreur */}
        {loading && (
          <div className="text-center py-16 text-[#9CA3AF]">
            <p className="animate-pulse text-lg">Chargement des idées…</p>
          </div>
        )}

        {error && (
          <div className="bg-red-900/20 border border-red-700/50 text-red-400 rounded-lg p-4 text-sm mb-6">
            {error}
          </div>
        )}

        {/* Grille des idées */}
        {!loading && !error && (
          <>
            {ideas.length === 0 ? (
              <div className="text-center py-16 text-[#9CA3AF]">
                <p className="text-5xl mb-4">🔍</p>
                <p className="text-lg font-medium text-white">Aucune idée ne correspond à vos filtres.</p>
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

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex justify-center items-center gap-3 mt-10">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="px-4 py-2 rounded-lg border border-[#1F2937] text-sm text-white hover:bg-[#1F2937] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  ← Précédent
                </button>
                <span className="text-sm text-[#9CA3AF]">
                  Page {page} / {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="px-4 py-2 rounded-lg border border-[#1F2937] text-sm text-white hover:bg-[#1F2937] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  Suivant →
                </button>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  )
}
