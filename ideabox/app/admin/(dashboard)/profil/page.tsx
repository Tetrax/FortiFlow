'use client'
import { useState } from 'react'
import { useSession } from 'next-auth/react'
import { inputClassSm } from '@/lib/styles'

export default function ProfilPage() {
  const { data: session } = useSession()

  const [form, setForm] = useState({ currentPassword: '', newPassword: '', confirm: '' })
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSuccess(false)

    if (form.newPassword !== form.confirm) {
      setError('Les mots de passe ne correspondent pas.')
      return
    }

    setSaving(true)
    try {
      const res = await fetch(`/api/admin/comptes/${session?.user?.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: form.currentPassword, newPassword: form.newPassword }),
      })
      const data = (await res.json()) as { error?: string }
      if (res.ok) {
        setSuccess(true)
        setForm({ currentPassword: '', newPassword: '', confirm: '' })
      } else {
        setError(data.error ?? 'Erreur lors du changement de mot de passe.')
      }
    } catch {
      setError('Erreur réseau. Réessayez.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-[var(--text-primary)]">👤 Mon profil</h1>
      </div>

      <div className="max-w-md">
        <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] p-6 mb-6">
          <h2 className="font-semibold text-[var(--text-primary)] mb-4">Informations</h2>
          <dl className="space-y-2 text-sm">
            <div className="flex gap-2">
              <dt className="text-[var(--text-secondary)] w-24 shrink-0">Nom</dt>
              <dd className="text-[var(--text-primary)] font-medium">{session?.user?.name ?? '—'}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-[var(--text-secondary)] w-24 shrink-0">Rôle</dt>
              <dd>
                <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                  session?.user?.role === 'ADMIN'
                    ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300'
                    : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                }`}>
                  {session?.user?.role === 'ADMIN' ? '🔑 Admin' : '🛡️ Modérateur'}
                </span>
              </dd>
            </div>
          </dl>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="bg-[var(--bg-card)] rounded-xl border border-[var(--border)] p-6 space-y-4">
          <h2 className="font-semibold text-[var(--text-primary)]">🔒 Changer le mot de passe</h2>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-700/50 dark:text-red-400 text-sm px-3 py-2 rounded-lg">
              {error}
            </div>
          )}
          {success && (
            <div className="bg-green-50 border border-green-200 text-green-700 dark:bg-green-900/20 dark:border-green-700/50 dark:text-green-400 text-sm px-3 py-2 rounded-lg">
              ✅ Mot de passe modifié avec succès.
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Mot de passe actuel</label>
            <input
              type="password"
              required
              value={form.currentPassword}
              onChange={(e) => setForm((f) => ({ ...f, currentPassword: e.target.value }))}
              className={inputClassSm}
              autoComplete="current-password"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Nouveau mot de passe</label>
            <input
              type="password"
              required
              minLength={8}
              value={form.newPassword}
              onChange={(e) => setForm((f) => ({ ...f, newPassword: e.target.value }))}
              placeholder="8 caractères minimum"
              className={inputClassSm}
              autoComplete="new-password"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-primary)] mb-1">Confirmer le nouveau mot de passe</label>
            <input
              type="password"
              required
              value={form.confirm}
              onChange={(e) => setForm((f) => ({ ...f, confirm: e.target.value }))}
              className={inputClassSm}
              autoComplete="new-password"
            />
          </div>

          <button
            type="submit"
            disabled={saving}
            className="w-full bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-medium py-2.5 rounded-lg hover:opacity-90 disabled:opacity-60 transition-opacity"
          >
            {saving ? 'Enregistrement…' : '💾 Enregistrer'}
          </button>
        </form>
      </div>
    </>
  )
}
