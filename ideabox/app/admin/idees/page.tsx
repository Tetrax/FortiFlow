// Liste de toutes les idées pour l'administration
export const dynamic = 'force-dynamic'

import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import AdminLayout from '@/components/AdminLayout'
import StatusBadge from '@/components/StatusBadge'
import Link from 'next/link'
import { IdeaStatus } from '@prisma/client'

interface PageProps {
  searchParams: Promise<{
    status?: string
    categoryId?: string
    page?: string
  }>
}

export default async function AdminIdeasPage({ searchParams }: PageProps) {
  // Vérification d'authentification
  const session = await auth()
  if (!session?.user) redirect('/admin/login')

  const sp = await searchParams
  const statusFilter = sp.status as IdeaStatus | undefined
  const categoryFilter = sp.categoryId
  const page = Math.max(1, parseInt(sp.page ?? '1', 10))
  const limit = 20
  const skip = (page - 1) * limit

  // Filtres
  const where = {
    ...(statusFilter && Object.values(IdeaStatus).includes(statusFilter)
      ? { status: statusFilter }
      : {}),
    ...(categoryFilter ? { categoryId: categoryFilter } : {}),
  }

  // Données
  const [ideas, total, categories] = await Promise.all([
    prisma.idea.findMany({
      where,
      include: { category: { select: { name: true, icon: true } } },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.idea.count({ where }),
    prisma.category.findMany({ where: { isActive: true }, orderBy: { name: 'asc' } }),
  ])

  const totalPages = Math.ceil(total / limit)

  // Construction de l'URL avec filtres
  function buildUrl(params: Record<string, string | undefined>) {
    const p = new URLSearchParams()
    const merged = { status: statusFilter, categoryId: categoryFilter, ...params }
    Object.entries(merged).forEach(([k, v]) => {
      if (v) p.set(k, v)
    })
    return `/admin/idees?${p.toString()}`
  }

  return (
    <AdminLayout adminName={session.user.name ?? undefined}>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">💡 Gestion des idées</h1>
        <span className="text-sm text-[#9CA3AF]">{total} idée{total > 1 ? 's' : ''}</span>
      </div>

      {/* Filtres */}
      <div className="flex flex-wrap gap-3 mb-6">
        {/* Filtre statut */}
        <div className="flex flex-wrap gap-2">
          {(['', ...Object.values(IdeaStatus)] as const).map((s) => (
            <Link
              key={s}
              href={buildUrl({ status: s || undefined, page: undefined })}
              className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                (statusFilter ?? '') === s
                  ? 'bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white border-[#6B21E8]'
                  : 'bg-[#111111] text-[#9CA3AF] border-[#1F2937] hover:border-[#6B21E8] hover:text-white'
              }`}
            >
              {s === '' ? 'Tous' : s}
            </Link>
          ))}
        </div>

        {/* Filtre catégorie */}
        <select
          defaultValue={categoryFilter ?? ''}
          onChange={(e) => {
            window.location.href = buildUrl({ categoryId: e.target.value || undefined, page: undefined })
          }}
          className="rounded-lg border border-[#1F2937] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8] bg-[#111111] text-white"
        >
          <option value="">Toutes les catégories</option>
          {categories.map((cat) => (
            <option key={cat.id} value={cat.id}>
              {cat.icon} {cat.name}
            </option>
          ))}
        </select>
      </div>

      {/* Table des idées */}
      <div className="bg-[#111111] rounded-xl border border-[#1F2937] overflow-hidden">
        {ideas.length === 0 ? (
          <p className="text-center text-[#9CA3AF] py-12 text-sm">Aucune idée ne correspond aux filtres.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-[#1A1A1A] border-b border-[#1F2937]">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-[#9CA3AF]">Titre</th>
                <th className="text-left px-4 py-3 font-medium text-[#9CA3AF] hidden sm:table-cell">Catégorie</th>
                <th className="text-left px-4 py-3 font-medium text-[#9CA3AF]">Statut</th>
                <th className="text-left px-4 py-3 font-medium text-[#9CA3AF] hidden md:table-cell">Votes</th>
                <th className="text-left px-4 py-3 font-medium text-[#9CA3AF] hidden md:table-cell">Date</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {ideas.map((idea) => (
                <tr key={idea.id} className="hover:bg-[#1A1A1A] transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium text-white line-clamp-1">{idea.title}</div>
                    <div className="text-xs text-[#9CA3AF] mt-0.5">
                      {idea.isAnonymous ? '🙈 Anonyme' : `👤 ${idea.authorName ?? idea.authorEmail ?? '?'}`}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-[#9CA3AF] hidden sm:table-cell">
                    {idea.category.icon} {idea.category.name}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={idea.status} />
                  </td>
                  <td className="px-4 py-3 text-[#9CA3AF] hidden md:table-cell">{idea.votesCount}</td>
                  <td className="px-4 py-3 text-[#9CA3AF] hidden md:table-cell">
                    {new Date(idea.createdAt).toLocaleDateString('fr-FR')}
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      href={`/admin/idees/${idea.id}`}
                      className="text-[#6B21E8] hover:underline text-xs font-medium"
                    >
                      Gérer →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-3 mt-6">
          {page > 1 && (
            <Link
              href={buildUrl({ page: String(page - 1) })}
              className="px-4 py-2 rounded-lg border border-[#1F2937] text-sm text-white hover:bg-[#1F2937] transition-colors"
            >
              ← Précédent
            </Link>
          )}
          <span className="text-sm text-[#9CA3AF]">
            Page {page} / {totalPages}
          </span>
          {page < totalPages && (
            <Link
              href={buildUrl({ page: String(page + 1) })}
              className="px-4 py-2 rounded-lg border border-[#1F2937] text-sm text-white hover:bg-[#1F2937] transition-colors"
            >
              Suivant →
            </Link>
          )}
        </div>
      )}
    </AdminLayout>
  )
}
