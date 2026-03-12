// Tableau de bord administrateur avec compteurs
export const dynamic = 'force-dynamic'

import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import AdminLayout from '@/components/AdminLayout'
import Link from 'next/link'
import { IdeaStatus } from '@prisma/client'

export default async function AdminDashboard() {
  // Vérification d'authentification
  const session = await auth()
  if (!session?.user) redirect('/admin/login')

  // Récupérer les statistiques
  const [totalIdeas, byStatus, recentIdeas] = await Promise.all([
    prisma.idea.count(),
    prisma.idea.groupBy({
      by: ['status'],
      _count: { status: true },
    }),
    prisma.idea.findMany({
      take: 5,
      orderBy: { createdAt: 'desc' },
      include: { category: { select: { name: true, icon: true } } },
    }),
  ])

  // Organiser les compteurs par statut
  const countByStatus = Object.fromEntries(
    byStatus.map((s) => [s.status, s._count.status])
  ) as Record<IdeaStatus, number>

  const stats = [
    { label: 'Idées totales', value: totalIdeas, icon: '💡', color: 'text-white' },
    { label: 'Nouvelles', value: countByStatus.NEW ?? 0, icon: '🆕', color: 'text-[#9CA3AF]' },
    { label: 'En examen', value: countByStatus.REVIEWING ?? 0, icon: '🔍', color: 'text-yellow-400' },
    { label: 'Acceptées', value: countByStatus.ACCEPTED ?? 0, icon: '✅', color: 'text-green-400' },
    { label: 'Réalisées', value: countByStatus.DONE ?? 0, icon: '🎉', color: 'text-purple-400' },
    { label: 'Refusées', value: countByStatus.REJECTED ?? 0, icon: '❌', color: 'text-red-400' },
  ]

  return (
    <AdminLayout adminName={session.user.name ?? undefined}>
      <h1 className="text-2xl font-bold text-white mb-8">📊 Tableau de bord</h1>

      {/* Compteurs */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-10">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="bg-[#111111] rounded-xl border border-[#1F2937] p-4 text-center"
          >
            <div className="text-2xl mb-1">{stat.icon}</div>
            <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-xs text-[#9CA3AF] mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Idées récentes */}
      <div className="bg-[#111111] rounded-xl border border-[#1F2937]">
        <div className="px-5 py-4 border-b border-[#1F2937] flex items-center justify-between">
          <h2 className="font-semibold text-white">Idées récentes</h2>
          <Link href="/admin/idees" className="text-sm text-[#6B21E8] hover:underline">
            Voir toutes →
          </Link>
        </div>
        <div className="divide-y divide-[#1F2937]">
          {recentIdeas.length === 0 ? (
            <p className="text-center text-[#9CA3AF] py-8 text-sm">Aucune idée soumise pour l'instant.</p>
          ) : (
            recentIdeas.map((idea) => (
              <Link
                key={idea.id}
                href={`/admin/idees/${idea.id}`}
                className="flex items-center justify-between px-5 py-3 hover:bg-[#1A1A1A] transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">{idea.title}</p>
                  <p className="text-xs text-[#9CA3AF]">
                    {idea.category.icon} {idea.category.name} ·{' '}
                    {new Date(idea.createdAt).toLocaleDateString('fr-FR')}
                  </p>
                </div>
                <span className="ml-3 text-xs text-[#9CA3AF]">→</span>
              </Link>
            ))
          )}
        </div>
      </div>
    </AdminLayout>
  )
}
