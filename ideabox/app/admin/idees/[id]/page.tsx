'use client'
// Page de gestion d'une idée côté admin (statut + réponse)
import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import AdminLayout from '@/components/AdminLayout'
import StatusBadge from '@/components/StatusBadge'
import { IdeaStatus } from '@prisma/client'
import Link from 'next/link'

interface Category {
  name: string
  icon: string
}

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

// Options de statut avec libellés
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
  const ideaId = params.id as string

  const [idea, setIdea] = useState<Idea | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  // Champs de formulaire
  const [status, setStatus] = useState<IdeaStatus>(IdeaStatus.NEW)
  const [adminResponse, setAdminResponse] = useState('')
  const [isVisible, setIsVisible] = useState(true)

  // Chargement de l'idée
  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(`/api/ideas/${ideaId}`)
        if (!res.ok) {
          if (res.status === 404) router.push('/admin/idees')
          return
        }
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

  // Sauvegarde des modifications
  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSuccess(false)

    try {
      const res = await fetch(`/api/admin/ideas/${ideaId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status,
          adminResponse: adminResponse || null,
          isVisible,
        }),
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
    'w-full rounded-lg border border-[#1F2937] bg-[#0A0A0A] text-white placeholder-[#4B5563] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8]'

  if (loading) {
    return (
      <AdminLayout>
        <div className="text-center py-16 text-[#9CA3AF] animate-pulse">Chargement…</div>
      </AdminLayout>
    )
  }

  if (!idea) {
    return (
      <AdminLayout>
        <div className="text-center py-16 text-[#9CA3AF]">Idée introuvable.</div>
      </AdminLayout>
    )
  }

  return (
    <AdminLayout>
      {/* Fil d'Ariane */}
      <div className="flex items-center gap-2 text-sm text-[#9CA3AF] mb-6">
        <Link href="/admin" className="hover:text-[#6B21E8] transition-colors">Dashboard</Link>
        <span>›</span>
        <Link href="/admin/idees" className="hover:text-[#6B21E8] transition-colors">Idées</Link>
        <span>›</span>
        <span className="text-white truncate max-w-xs">{idea.title}</span>
      </div>

      <div className="grid lg:grid-cols-5 gap-6">
        {/* Détail de l'idée */}
        <div className="lg:col-span-3 space-y-4">
          <div className="bg-[#111111] rounded-xl border border-[#1F2937] p-6">
            <div className="flex flex-wrap gap-2 mb-3">
              <span className="text-sm bg-[#1F2937] text-[#9CA3AF] px-2.5 py-1 rounded-full">
                {idea.category.icon} {idea.category.name}
              </span>
              <StatusBadge status={idea.status} />
              {!idea.isVisible && (
                <span className="text-sm bg-orange-900/30 text-orange-400 px-2.5 py-1 rounded-full">
                  🚫 Masquée
                </span>
              )}
            </div>
            <h1 className="text-xl font-bold text-white mb-2">{idea.title}</h1>
            <div className="text-sm text-[#9CA3AF] mb-4">
              {idea.isAnonymous ? '🙈 Anonyme' : `👤 ${idea.authorName ?? 'N/A'}`}
              {!idea.isAnonymous && idea.authorEmail && ` · ✉️ ${idea.authorEmail}`}
              {' · '}
              {new Date(idea.createdAt).toLocaleDateString('fr-FR', {
                day: 'numeric', month: 'long', year: 'numeric',
              })}
              {' · '}
              👍 {idea.votesCount} vote{idea.votesCount !== 1 ? 's' : ''}
            </div>
            <p className="text-white whitespace-pre-wrap leading-relaxed">
              {idea.description}
            </p>
          </div>
        </div>

        {/* Formulaire de gestion */}
        <div className="lg:col-span-2">
          <form onSubmit={handleSave} className="bg-[#111111] rounded-xl border border-[#1F2937] p-6 space-y-5 sticky top-24">
            <h2 className="font-semibold text-white">⚙️ Gestion</h2>

            {/* Messages */}
            {error && (
              <div className="bg-red-900/20 border border-red-700/50 text-red-400 text-sm px-3 py-2 rounded-lg">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-green-900/20 border border-green-700/50 text-green-400 text-sm px-3 py-2 rounded-lg">
                ✅ Modifications enregistrées !
              </div>
            )}

            {/* Statut */}
            <div>
              <label className="block text-sm font-medium text-white mb-1">
                Statut
              </label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as IdeaStatus)}
                className={inputClass}
              >
                {STATUS_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>

            {/* Réponse officielle */}
            <div>
              <label className="block text-sm font-medium text-white mb-1">
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
              <p className="text-xs text-[#9CA3AF] mt-1">{adminResponse.length}/1000</p>
            </div>

            {/* Visibilité */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={isVisible}
                onChange={(e) => setIsVisible(e.target.checked)}
                className="h-4 w-4 rounded border-[#1F2937] text-[#6B21E8] focus:ring-[#6B21E8] bg-[#0A0A0A]"
              />
              <span className="text-sm text-white">Visible publiquement</span>
            </label>

            {/* Bouton sauvegarder */}
            <button
              type="submit"
              disabled={saving}
              className="w-full bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-medium py-2.5 rounded-lg hover:opacity-90 disabled:opacity-60 transition-opacity"
            >
              {saving ? 'Enregistrement…' : '💾 Enregistrer'}
            </button>

            {/* Lien vers la vue publique */}
            <Link
              href={`/idees/${idea.id}`}
              target="_blank"
              className="block text-center text-sm text-[#9CA3AF] hover:text-[#6B21E8] transition-colors"
            >
              Voir la vue publique ↗
            </Link>
          </form>
        </div>
      </div>
    </AdminLayout>
  )
}
