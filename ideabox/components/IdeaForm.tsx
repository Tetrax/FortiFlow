'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'

interface Category {
  id: string
  name: string
  icon: string
}

interface IdeaFormProps {
  categories: Category[]
}

export default function IdeaForm({ categories }: IdeaFormProps) {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isAnonymous, setIsAnonymous] = useState(true)

  const [form, setForm] = useState({
    title: '',
    description: '',
    categoryId: '',
    authorName: '',
    authorEmail: '',
  })

  function handleChange(
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)

    if (!form.title.trim() || !form.description.trim() || !form.categoryId) {
      setError('Veuillez remplir tous les champs obligatoires.')
      setLoading(false)
      return
    }

    try {
      const res = await fetch('/api/ideas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...form,
          isAnonymous,
          authorName: isAnonymous ? undefined : form.authorName,
          authorEmail: isAnonymous ? undefined : form.authorEmail,
        }),
      })

      if (res.ok) {
        const data = (await res.json()) as { id: string }
        router.push(`/idees/${data.id}?submitted=1`)
      } else {
        const data = (await res.json()) as { error?: string }
        setError(data.error ?? 'Une erreur est survenue. Réessayez.')
      }
    } catch {
      setError('Erreur réseau. Vérifiez votre connexion.')
    } finally {
      setLoading(false)
    }
  }

  const inputClass =
    'w-full rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] text-[var(--text-primary)] placeholder-gray-400 px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#6B21E8]'

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-700/50 dark:text-red-400 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      <div>
        <label htmlFor="title" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
          Titre de l'idée <span className="text-red-500">*</span>
        </label>
        <input
          id="title"
          name="title"
          type="text"
          value={form.title}
          onChange={handleChange}
          placeholder="Résumez votre idée en une phrase"
          maxLength={150}
          className={inputClass}
          required
        />
        <p className="mt-1 text-xs text-[var(--text-secondary)]">{form.title.length}/150 caractères</p>
      </div>

      <div>
        <label htmlFor="description" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
          Description <span className="text-red-500">*</span>
        </label>
        <textarea
          id="description"
          name="description"
          value={form.description}
          onChange={handleChange}
          rows={5}
          placeholder="Décrivez votre idée en détail : le problème, la solution proposée, les bénéfices attendus…"
          maxLength={2000}
          className={`${inputClass} resize-none`}
          required
        />
        <p className="mt-1 text-xs text-[var(--text-secondary)]">{form.description.length}/2000 caractères</p>
      </div>

      <div>
        <label htmlFor="categoryId" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
          Catégorie <span className="text-red-500">*</span>
        </label>
        <select
          id="categoryId"
          name="categoryId"
          value={form.categoryId}
          onChange={handleChange}
          className={inputClass}
          required
        >
          <option value="">Choisissez une catégorie</option>
          {categories.map((cat) => (
            <option key={cat.id} value={cat.id}>
              {cat.icon} {cat.name}
            </option>
          ))}
        </select>
      </div>

      <div className="bg-[var(--bg-accent)] border border-[#6B21E8]/30 rounded-lg p-4">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={isAnonymous}
            onChange={(e) => setIsAnonymous(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-[var(--border)] text-[#6B21E8] focus:ring-[#6B21E8]"
          />
          <div>
            <span className="text-sm font-medium text-[var(--text-primary)]">Soumettre anonymement</span>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              Votre identité ne sera pas affichée publiquement. Le CSE peut voir votre email si fourni, uniquement pour vous recontacter.
            </p>
          </div>
        </label>
      </div>

      {!isAnonymous && (
        <div className="grid sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="authorName" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
              Votre nom
            </label>
            <input
              id="authorName"
              name="authorName"
              type="text"
              value={form.authorName}
              onChange={handleChange}
              placeholder="Prénom Nom"
              className={inputClass}
            />
          </div>
          <div>
            <label htmlFor="authorEmail" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
              Votre email
            </label>
            <input
              id="authorEmail"
              name="authorEmail"
              type="email"
              value={form.authorEmail}
              onChange={handleChange}
              placeholder="vous@entreprise.fr"
              className={inputClass}
            />
          </div>
        </div>
      )}

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-medium py-3 px-6 rounded-lg hover:opacity-90 active:scale-[0.99] transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed"
      >
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <span className="animate-spin">⏳</span> Envoi en cours…
          </span>
        ) : (
          '💡 Soumettre mon idée'
        )}
      </button>

      <p className="text-xs text-[var(--text-secondary)] text-center">
        En soumettant, vous acceptez notre{' '}
        <a href="/rgpd" className="underline hover:text-[var(--text-primary)] transition-colors">
          politique RGPD
        </a>
        .
      </p>
    </form>
  )
}
