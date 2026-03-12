export const dynamic = 'force-dynamic'

import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import AdminLayout from '@/components/AdminLayout'
import Link from 'next/link'
import { IdeaStatus } from '@prisma/client'

export default async function AdminDashboard() {
  const session = await auth()
  if (!session?.user) redirect('/admin/login')

  const [totalIdeas, byStatus, recentIdeas] = await Promise.all([
    prisma.idea.count(),
    prisma.idea.groupBy({ by: ['status'], _count: { status: true } }),
    prisma.idea.findMany({
      take: 5,
      orderBy: { createdAt: 'desc' },
      include: { category: { select: { name: true, icon: true } } },
    }),
  ])

  const countByStatus = Object.fromEntries(
    byStatus.map((s) => [s.status, s._count.status])
  ) as Record<IdeaStatus, number>

  const stats = [
    { label: 'Idées totales', value: totalIdeas, icon: '💡', color: 'text-[var(--text-primary)]' },
    { label: 'Nouvelles', value: countByStatus.NEW ?? 0, icon: '🆕', color: 'text-[var(--text-secondary)]' },
    { label: 'En examen', value: countByStatus.REVIEWING ?? 0, icon: '🔍', color: 'text-yellow-500 dark:text-yellow-400' },
    { label: 'Acceptées', value: countByStatus.ACCEPTED ?? 0, icon: '✅', color: 'text-green-600 dark:text-green-400' },
    { label: 'Réalisées', value: countByStatus.DONE ?? 0, icon: '🎉', color: 'text-purple-600 dark:text-purple-400' },
    { label: 'Refusées', value: countByStatus.REJECTED ?? 0, icon: '❌', color: 'text-red-600 dark:text-red-400' },
  ]

  return (
    <AdminLayout adminName={session.user.name ?? undefined}>
      <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-8">📊 Tableau de bord</h1>

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
    </AdminLayout>
  )
}
