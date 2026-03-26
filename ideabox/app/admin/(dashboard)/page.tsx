export const dynamic = 'force-dynamic'

import { auth } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import Link from 'next/link'
import { IdeaStatus } from '@prisma/client'
import DashboardCharts from '@/components/DashboardCharts'

export default async function AdminDashboard() {
  const session = await auth()

  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)

  const [totalIdeas, byStatus, recentIdeas, byCategory, recentVotes] = await Promise.all([
    prisma.idea.count(),
    prisma.idea.groupBy({ by: ['status'], _count: { status: true } }),
    prisma.idea.findMany({
      take: 5,
      orderBy: { createdAt: 'desc' },
      include: { category: { select: { name: true, icon: true } } },
    }),
    prisma.category.findMany({
      where: { isActive: true },
      include: { _count: { select: { ideas: true } } },
      orderBy: { name: 'asc' },
    }),
    prisma.vote.findMany({
      where: { createdAt: { gte: thirtyDaysAgo } },
      select: { createdAt: true },
    }),
  ])

  const countByStatus = Object.fromEntries(
    byStatus.map((s) => [s.status, s._count.status])
  ) as Record<IdeaStatus, number>

  // Taux d'acceptation
  const accepted = (countByStatus.ACCEPTED ?? 0) + (countByStatus.DONE ?? 0)
  const acceptanceRate = totalIdeas > 0 ? Math.round((accepted / totalIdeas) * 100) : 0

  // Catégories pour le graphique
  const categoryChartData = byCategory.map((c) => ({
    name: c.name,
    icon: c.icon,
    count: c._count.ideas,
  }))

  // Votes par jour sur 30 jours
  const votesMap: Record<string, number> = {}
  for (const vote of recentVotes) {
    const day = vote.createdAt.toISOString().slice(0, 10)
    votesMap[day] = (votesMap[day] ?? 0) + 1
  }
  const votesTimeline = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(thirtyDaysAgo.getTime() + i * 24 * 60 * 60 * 1000)
    const key = d.toISOString().slice(0, 10)
    const label = d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' })
    return { date: label, votes: votesMap[key] ?? 0 }
  })

  const stats = [
    { label: 'Idées totales', value: totalIdeas, icon: '💡', color: 'text-[var(--text-primary)]' },
    { label: 'Nouvelles', value: countByStatus.NEW ?? 0, icon: '🆕', color: 'text-[var(--text-secondary)]' },
    { label: 'En examen', value: countByStatus.REVIEWING ?? 0, icon: '🔍', color: 'text-yellow-500 dark:text-yellow-400' },
    { label: 'Acceptées', value: countByStatus.ACCEPTED ?? 0, icon: '✅', color: 'text-green-600 dark:text-green-400' },
    { label: 'Réalisées', value: countByStatus.DONE ?? 0, icon: '🎉', color: 'text-purple-600 dark:text-purple-400' },
    { label: 'Refusées', value: countByStatus.REJECTED ?? 0, icon: '❌', color: 'text-red-600 dark:text-red-400' },
  ]

  return (
    <>
      <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-8">📊 Tableau de bord</h1>

      <DashboardCharts
        byCategory={categoryChartData}
        votesTimeline={votesTimeline}
        acceptanceRate={acceptanceRate}
      />

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-10">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] p-4 text-center">
            <div className="text-2xl mb-1">{stat.icon}</div>
            <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)]">
        <div className="px-5 py-4 border-b border-[var(--border)] flex items-center justify-between">
          <h2 className="font-semibold text-[var(--text-primary)]">Idées récentes</h2>
          <Link href="/admin/idees" className="text-sm text-[#6B21E8] hover:underline">
            Voir toutes →
          </Link>
        </div>
        <div className="divide-y divide-[var(--border)]">
          {recentIdeas.length === 0 ? (
            <p className="text-center text-[var(--text-secondary)] py-8 text-sm">Aucune idée soumise pour l'instant.</p>
          ) : (
            recentIdeas.map((idea) => (
              <Link
                key={idea.id}
                href={`/admin/idees/${idea.id}`}
                className="flex items-center justify-between px-5 py-3 hover:bg-[var(--bg-hover)] transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-[var(--text-primary)] truncate">{idea.title}</p>
                  <p className="text-xs text-[var(--text-secondary)]">
                    {idea.category.icon} {idea.category.name} · {new Date(idea.createdAt).toLocaleDateString('fr-FR')}
                  </p>
                </div>
                <span className="ml-3 text-xs text-[var(--text-secondary)]">→</span>
              </Link>
            ))
          )}
        </div>
      </div>
    </>
  )
}
