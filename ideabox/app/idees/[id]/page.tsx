// Page de détail d'une idée
// Rendu dynamique car dépend de la base de données
export const dynamic = 'force-dynamic'

import { notFound } from 'next/navigation'
import Link from 'next/link'
import Image from 'next/image'
import { prisma } from '@/lib/prisma'
import StatusBadge from '@/components/StatusBadge'
import VoteButton from '@/components/VoteButton'

interface PageProps {
  params: Promise<{ id: string }>
  searchParams: Promise<{ submitted?: string }>
}

export default async function IdeaDetailPage({ params, searchParams }: PageProps) {
  const { id } = await params
  const { submitted } = await searchParams

  // Récupérer l'idée depuis la base de données
  const idea = await prisma.idea.findFirst({
    where: { id, isVisible: true },
    include: {
      category: { select: { name: true, icon: true } },
    },
  })

  if (!idea) notFound()

  const date = new Date(idea.createdAt).toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })

  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* Barre de navigation */}
      <nav className="bg-[#111111] border-b border-[#1F2937]">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center gap-2 text-sm text-[#9CA3AF]">
          <Link href="/" className="hover:opacity-80 transition-opacity flex items-center">
            <Image src="/logo-sns.svg" alt="SNS Security" width={60} height={32} className="h-5 w-auto" />
          </Link>
          <span>›</span>
          <Link href="/idees" className="hover:text-[#6B21E8] transition-colors">Les idées</Link>
          <span>›</span>
          <span className="text-white truncate max-w-xs">{idea.title}</span>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {/* Message de confirmation après soumission */}
        {submitted === '1' && (
          <div className="bg-green-900/20 border border-green-700/50 text-green-400 rounded-xl p-4 mb-6 flex items-start gap-3">
            <span className="text-xl">🎉</span>
            <div>
              <p className="font-medium">Votre idée a bien été reçue !</p>
              <p className="text-sm mt-1">
                Elle sera examinée par le CSE dans les meilleurs délais.
                {idea.authorEmail && ' Vous recevrez un email de confirmation.'}
              </p>
            </div>
          </div>
        )}

        {/* Carte principale */}
        <article className="bg-[#111111] rounded-2xl border border-[#1F2937] shadow-sm overflow-hidden">
          {/* En-tête */}
          <div className="p-6 border-b border-[#1F2937]">
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <span className="text-sm bg-[#1F2937] text-[#9CA3AF] px-2.5 py-1 rounded-full">
                {idea.category.icon} {idea.category.name}
              </span>
              <StatusBadge status={idea.status} />
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white">{idea.title}</h1>
            <div className="flex items-center gap-3 mt-3 text-sm text-[#9CA3AF]">
              <span>
                {idea.isAnonymous ? '🙈 Anonyme' : `👤 ${idea.authorName ?? 'Inconnu'}`}
              </span>
              <span>·</span>
              <span>📅 {date}</span>
            </div>
          </div>

          {/* Description */}
          <div className="p-6">
            <h2 className="text-sm font-semibold text-[#9CA3AF] uppercase tracking-wide mb-3">
              Description
            </h2>
            <p className="text-white leading-relaxed whitespace-pre-wrap">
              {idea.description}
            </p>
          </div>

          {/* Réponse officielle du CSE (si existante) */}
          {idea.adminResponse && (
            <div className="p-6 bg-[#1e1040] border-t border-[#6B21E8]/30">
              <h2 className="text-sm font-semibold text-purple-400 uppercase tracking-wide mb-3">
                📣 Réponse officielle du CSE
              </h2>
              <p className="text-purple-200 leading-relaxed whitespace-pre-wrap">
                {idea.adminResponse}
              </p>
            </div>
          )}

          {/* Pied : votes */}
          <div className="p-6 border-t border-[#1F2937] flex items-center justify-between">
            <span className="text-sm text-[#9CA3AF]">
              Soutenu par {idea.votesCount} personne{idea.votesCount !== 1 ? 's' : ''}
            </span>
            <VoteButton ideaId={idea.id} initialCount={idea.votesCount} />
          </div>
        </article>

        {/* Retour */}
        <div className="mt-6 text-center">
          <Link
            href="/idees"
            className="text-sm text-[#9CA3AF] hover:text-[#6B21E8] transition-colors"
          >
            ← Retour au mur des idées
          </Link>
        </div>
      </main>
    </div>
  )
}
