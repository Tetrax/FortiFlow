export const dynamic = 'force-dynamic'

import Link from 'next/link'
import Image from 'next/image'
import { prisma } from '@/lib/prisma'
import IdeaForm from '@/components/IdeaForm'

export default async function SoumettreePage() {
  const categories = await prisma.category.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
  })

  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <nav className="bg-[var(--bg-card)] border-b border-[var(--border)]">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center gap-2 text-sm text-[var(--text-secondary)]">
          <Link href="/" className="hover:opacity-80 transition-opacity flex items-center">
            <Image src="/logo-sns.svg" alt="SNS Security" width={60} height={32} className="h-5 w-auto" />
          </Link>
          <span>›</span>
          <span className="text-[var(--text-primary)]">Soumettre une idée</span>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="mb-6 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/50 rounded-xl p-4 text-sm text-amber-800 dark:text-amber-300 flex items-start gap-3">
          <span className="text-xl shrink-0">⚠️</span>
          <p>
            <strong>Information importante :</strong> Seules les idées retenues par le CSE sont affichées publiquement.
            Si votre idée n'apparaît pas, c'est qu'elle n'a pas été validée pour publication — elle a néanmoins bien été reçue et examinée par notre équipe.
          </p>
        </div>

        <div className="text-center mb-10">
          <h1 className="text-3xl font-bold text-[var(--text-primary)] mb-3">💡 Soumettre une idée</h1>
          <p className="text-[var(--text-secondary)] max-w-xl mx-auto">
            Vous avez une idée pour améliorer votre entreprise ?
            Partagez-la ! Toutes les suggestions sont lues et étudiées par le CSE.
          </p>
        </div>

        <div className="bg-[var(--bg-card)] rounded-2xl border border-[var(--border)] shadow-sm p-6 sm:p-8">
          <IdeaForm categories={categories} />
        </div>

        <div className="mt-4 bg-[var(--bg-accent)] border border-[#6B21E8]/30 rounded-xl p-4 text-sm text-[var(--text-on-accent)] flex items-start gap-3">
          <span className="text-xl shrink-0">🔒</span>
          <p>
            <strong className="text-[var(--text-primary)]">Votre confidentialité est protégée.</strong> Par défaut, votre idée est
            soumise anonymement. Aucune information personnelle n'est rendue publique sans
            votre accord. Consultez notre{' '}
            <Link href="/rgpd" className="underline hover:text-[var(--text-primary)] transition-colors">
              politique RGPD
            </Link>
            .
          </p>
        </div>
      </main>
    </div>
  )
}
