'use client'
import { useEffect, useState } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { inputClassSm } from '@/lib/styles'

interface AdminAccount {
  id: string
  username: string
  email: string | null
  name: string
  role: 'ADMIN' | 'MODERATOR'
  createdAt: string
}

export default function AdminComptesPage() {
  const { data: session, status } = useSession()
  const router = useRouter()

  const [admins, setAdmins] = useState<AdminAccount[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const [form, setForm] = useState({ username: '', name: '', email: '', role: 'MODERATOR', password: '' })
  const [formError, setFormError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (status === 'unauthenticated') router.push('/admin/login')
    if (status === 'authenticated' && session.user.role !== 'ADMIN') router.push('/admin')
  }, [status, session, router])

  useEffect(() => {
    if (status !== 'authenticated' || session?.user?.role !== 'ADMIN') return
    void fetchAdmins()
  }, [status, session])

  async function fetchAdmins() {
    setLoading(true)
    try {
      const res = await fetch('/api/admin/comptes')
      if (res.ok) setAdmins((await res.json()) as AdminAccount[])
    } finally {
      setLoading(false)
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setFormError(null)
    setSuccess(null)
    setSubmitting(true)
    try {
      const res = await fetch('/api/admin/comptes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const data = (await res.json()) as { error?: string }
      if (res.ok) {
        setSuccess(`Compte créé pour @${form.username}`)
        setForm({ username: '', name: '', email: '', role: 'MODERATOR', password: '' })
        void fetchAdmins()
      } else {
        setFormError(data.error ?? 'Erreur lors de la création.')
      }
    } catch {
      setFormError('Erreur réseau. Réessayez.')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleDelete(id: string, name: string) {
    if (!confirm(`Supprimer le compte de ${name} ?`)) return
    setError(null)
    setDeleting(id)
    try {
      const res = await fetch(`/api/admin/comptes/${id}`, { method: 'DELETE' })
      const data = (await res.json()) as { error?: string }
      if (res.ok) {
        setAdmins((prev) => prev.filter((a) => a.id !== id))
      } else {
        setError(data.error ?? 'Erreur lors de la suppression.')
      }
    } catch {
      setError('Erreur réseau. Réessayez.')
    } finally {
      setDeleting(null)
    }
  }

  if (status === 'loading' || (status === 'authenticated' && session?.user?.role !== 'ADMIN')) {
    return <div className="text-center py-16 text-[var(--text-secondary)] animate-pulse">Chargement…</div>
  }

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-[var(--text-primary)]">👥 Gestion des comptes</h1>
        <span className="text-sm text-[var(--text-secondary)]">{admins.length} compte{admins.length > 1 ? 's' : ''}</span>
      </div>

      <div className="grid lg:grid-cols-5 gap-6">
        {/* Liste des comptes */}
        <div className="lg:col-span-3">
          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-700/50 dark:text-red-400 text-sm px-3 py-2 rounded-lg">
              {error}
            </div>
          )}

          <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] overflow-hidden">
            {loading ? (
              <p className="text-center text-[var(--text-secondary)] py-12 text-sm animate-pulse">Chargement…</p>
            ) : admins.length === 0 ? (
              <p className="text-center text-[var(--text-secondary)] py-12 text-sm">Aucun compte.</p>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-[var(--bg-hover)] border-b border-[var(--border)]">
                  <tr>
                    <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Nom</th>
                    <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)] hidden sm:table-cell">Identifiant</th>
                    <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Rôle</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {admins.map((admin) => (
                    <tr key={admin.id} className="hover:bg-[var(--bg-hover)] transition-colors">
                      <td className="px-4 py-3">
                        <div className="font-medium text-[var(--text-primary)]">{admin.name}</div>
                        <div className="text-xs text-[var(--text-secondary)] sm:hidden">@{admin.username}</div>
                      </td>
                      <td className="px-4 py-3 text-[var(--text-secondary)] hidden sm:table-cell">@{admin.username}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                          admin.role === 'ADMIN'
                            ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300'
                            : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                        }`}>
                          {admin.role === 'ADMIN' ? '🔑 Admin' : '🛡️ Modérateur'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        {admin.id !== session?.user?.id && (
                          <button
                            onClick={() => void handleDelete(admin.id, admin.name)}
                            disabled={deleting === admin.id}
                            className="text-xs text-red-500 hover:text-red-400 font-medium disabled:opacity-50"
                          >
                            {deleting === admin.id ? '…' : 'Supprimer'}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Formulaire de création */}
        <div className="lg:col-span-2">
          <form onSubmit={(e) => void handleCreate(e)} className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] p-6 space-y-4 sticky top-24">
            <h2 className="font-semibold text-[var(--text-primary)]">➕ Nouveau compte</h2>

            {formError && (
              <div className="bg-red-50 border border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-700/50 dark:text-red-400 text-sm px-3 py-2 rounded-lg">
                {formError}
              </div>
            )}
            {success && (
              <div className="bg-green-50 border border-green-200 text-green-700 dark:bg-green-900/20 dark:border-green-700/50 dark:text-green-400 text-sm px-3 py-2 rounded-lg">
                ✅ {success}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Nom d'utilisateur</label>
              <input
                type="text"
                required
                value={form.username}
                onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                placeholder="jean_dupont"
                className={inputClassSm}
              />
              <p className="text-xs text-[var(--text-secondary)] mt-1">Lettres, chiffres, - et _ uniquement</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Nom complet</label>
              <input
                type="text"
                required
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="Jean Dupont"
                className={inputClassSm}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Email <span className="text-[var(--text-secondary)] font-normal">(optionnel, pour les notifications)</span></label>
              <input
                type="email"
                value={form.email}
                onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                placeholder="jean@entreprise.fr"
                className={inputClassSm}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Rôle</label>
              <select
                value={form.role}
                onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}
                className={inputClassSm}
              >
                <option value="MODERATOR">🛡️ Modérateur</option>
                <option value="ADMIN">🔑 Administrateur</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Mot de passe</label>
              <input
                type="password"
                required
                value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                placeholder="8 caractères minimum"
                className={inputClassSm}
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-medium py-2.5 rounded-lg hover:opacity-90 disabled:opacity-60 transition-opacity"
            >
              {submitting ? 'Création…' : '➕ Créer le compte'}
            </button>
          </form>
        </div>
      </div>
    </>
  )
}
