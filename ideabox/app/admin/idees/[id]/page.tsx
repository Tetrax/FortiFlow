'use client'
import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useSession } from 'next-auth/react'
import AdminLayout from '@/components/AdminLayout'
import StatusBadge from '@/components/StatusBadge'
import { IdeaStatus } from '@prisma/client'
import Link from 'next/link'

interface Category { name: string; icon: string }

interface Idea {
  id: string
  title: string
  description: string
  status: IdeaStatus
  adminResponse: string | null
  isAnonymous: boolean
  authorName: string | null
  authorEmail: string | null
  votesCount: number
  isVisible: boolean
  createdAt: string
  category: Category
}

const STATUS_OPTIONS: Array<{ value: IdeaStatus; label: string }> = [
  { value: IdeaStatus.NEW, label: '🆕 Nouvelle' },
  { value: IdeaStatus.REVIEWING, label: '🔍 En examen' },
  { value: IdeaStatus.ACCEPTED, label: '✅ Acceptée' },
  { value: IdeaStatus.REJECTED, label: '❌ Refusée' },
  { value: IdeaStatus.DONE, label: '🎉 Réalisée' },
]

export default function AdminIdeaPage() {
  const params = useParams()
  const router = useRouter()
  const { data: session } = useSession()
  const ideaId = params.id as string

  const [idea, setIdea] = useState<Idea | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [status, setStatus] = useState<IdeaStatus>(IdeaStatus.NEW)
  const [adminResponse, setAdminResponse] = useState('')
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(`/api/ideas/${ideaId}`)
        if (!res.ok) { if (res.status === 404) router.push('/admin/idees'); return }
        const data = (await res.json()) as Idea
        setIdea(data)
        setStatus(data.status)
        setAdminResponse(data.adminResponse ?? '')
        setIsVisible(data.isVisible)
      } catch {
        setError('Impossible de charger cette idée.')
      } finally {
        setLoading(false)
      }
    }
    void load()
  }, [ideaId, router])

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSuccess(false)

    try {
      const res = await fetch(`/api/admin/ideas/${ideaId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, adminResponse: adminResponse || null, isVisible }),
      })

      if (res.ok) {
        setSuccess(true)
        setTimeout(() => setSuccess(false), 3000)
        const updated = (await res.json()) as Idea
        setIdea(updated)
      } else if (res.status === 401) {
        router.push('/admin/login')
      } else {
        const data = (await res.json()) as { error?: string }
        setError(data.error ?? 'Erreur lors de la sauvegarde.')
      }
    } catch {
      setError('Erreur réseau. Réessayez.')
    } finally {
      setSaving(false)
    }
  }

  const inputClass =
    'w-full rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] text-[var(--text-primary)] placeholder-gray-400 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8]'

  const adminRole = session?.user?.role ?? undefined

  if (loading) return <AdminLayout adminRole={adminRole}><div className="text-center py-16 text-[var(--text-secondary)] animate-pulse">Chargement…</div></AdminLayout>
  if (!idea) return <AdminLayout adminRole={adminRole}><div className="text-center py-16 text-[var(--text-secondary)]">Idée introuvable.</div></AdminLayout>

  return (
    <AdminLayout adminRole={adminRole}>
      <div className="flex items-center gap-2 text-sm text-[var(--text-secondary)] mb-6">
        <Link href="/admin" className="hover:text-[#6B21E8] transition-colors">Dashboard</Link>
        <span>›</span>
        <Link href="/admin/idees" className="hover:text-[#6B21E8] transition-colors">Idées</Link>
        <span>›</span>
        <span className="text-[var(--text-primary)] truncate max-w-xs">{idea.title}</span>
      </div>

      <div className="grid lg:grid-cols-5 gap-6">
        <div className="lg:col-span-3 space-y-4">
          <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex flex-wrap gap-2 mb-3">
              <span className="text-sm bg-[var(--bg-hover)] text-[var(--text-secondary)] px-2.5 py-1 rounded-full">
                {idea.category.icon} {idea.category.name}
              </span>
              <StatusBadge status={idea.status} />
              {!idea.isVisible && (
                <span className="text-sm bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 px-2.5 py-1 rounded-full">
                  🚫 Masquée
                </span>
              )}
            </div>
            <h1 className="text-xl font-bold text-[var(--text-primary)] mb-2">{idea.title}</h1>
            <div className="text-sm text-[var(--text-secondary)] mb-4">
              {idea.isAnonymous ? '🙈 Anonyme' : `👤 ${idea.authorName ?? 'N/A'}`}
              {!idea.isAnonymous && idea.authorEmail && ` · ✉️ ${idea.authorEmail}`}
              {' · '}
              {new Date(idea.createdAt).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })}
              {' · '}
              👍 {idea.votesCount} vote{idea.votesCount !== 1 ? 's' : ''}
            </div>
            <p className="text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed">
              {idea.description}
            </p>
          </div>
        </div>

        <div className="lg:col-span-2">
          <form onSubmit={handleSave} className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] p-6 space-y-5 sticky top-24">
            <h2 className="font-semibold text-[var(--text-primary)]">⚙️ Gestion</h2>

            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-700/50 dark:text-red-400 text-sm px-3 py-2 rounded-lg">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-green-50 border border-green-200 text-green-700 dark:bg-green-900/20 dark:border-green-700/50 dark:text-green-400 text-sm px-3 py-2 rounded-lg">
                ✅ Modifications enregistrées !
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Statut</label>
              <select value={status} onChange={(e) => setStatus(e.target.value as IdeaStatus)} className={inputClass}>
                {STATUS_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">
                Réponse officielle du CSE
              </label>
              <textarea
                value={adminResponse}
                onChange={(e) => setAdminResponse(e.target.value)}
                rows={5}
                maxLength={1000}
                placeholder="Expliquez la décision, les prochaines étapes…"
                className={`${inputClass} resize-none`}
              />
              <p className="text-xs text-[var(--text-secondary)] mt-1">{adminResponse.length}/1000</p>
            </div>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={isVisible}
                onChange={(e) => setIsVisible(e.target.checked)}
                className="h-4 w-4 rounded border-[var(--border)] text-[#6B21E8] focus:ring-[#6B21E8]"
              />
              <span className="text-sm text-[var(--text-primary)]">Visible publiquement</span>
            </label>

            <button
              type="submit"
              disabled={saving}
              className="w-full bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-medium py-2.5 rounded-lg hover:opacity-90 disabled:opacity-60 transition-opacity"
            >
              {saving ? 'Enregistrement…' : '💾 Enregistrer'}
            </button>

            <Link
              href={`/idees/${idea.id}`}
              target="_blank"
              className="block text-center text-sm text-[var(--text-secondary)] hover:text-[#6B21E8] transition-colors"
            >
              Voir la vue publique ↗
            </Link>
          </form>
        </div>
      </div>
    </AdminLayout>
  )
}
