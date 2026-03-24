// Page d'accueil publique
import Link from 'next/link'
import Image from 'next/image'
import ThemeToggle from '@/components/ThemeToggle'

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      {/* Barre de navigation */}
      <nav className="border-b border-[var(--border)] bg-[var(--bg-card)]/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Image
              src="/logo-sns.svg"
              alt="SNS Security"
              width={90}
              height={48}
              className="h-8 w-auto dark:opacity-100 opacity-90"
            />
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/idees"
              className="text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] font-medium transition-colors"
            >
              Les idées
            </Link>
            <ThemeToggle />
            <Link
              href="/soumettre"
              className="text-sm bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white px-4 py-2 rounded-lg font-medium transition-opacity hover:opacity-90"
            >
              Soumettre
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero avec la panthère */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0">
          <Image
            src="/panthere-sns.jpg"
            alt="SNS Security"
            fill
            className="object-cover object-center opacity-45"
            priority
          />
          <div className="absolute inset-0 bg-gradient-to-b from-[var(--bg-primary)]/30 via-[var(--bg-primary)]/40 to-[var(--bg-primary)]" />
        </div>

        <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-28 text-center">
          <div className="flex justify-center mb-8">
            <Image
              src="/logo-sns.svg"
              alt="SNS Security"
              width={200}
              height={105}
              className="h-16 w-auto opacity-90"
            />
          </div>

          <p className="text-sm font-semibold tracking-widest text-[var(--text-secondary)] uppercase mb-4">
            Boîte à Idées — CSE
          </p>

          <h1 className="text-4xl sm:text-5xl font-bold text-[var(--text-primary)] mb-6 leading-tight">
            Votre voix compte.{' '}
            <span className="bg-gradient-to-r from-[#6B21E8] to-[#2563EB] bg-clip-text text-transparent">
              Partagez vos idées.
            </span>
          </h1>
          <p className="text-xl text-[var(--text-secondary)] mb-10 max-w-2xl mx-auto">
            Un espace sécurisé pour proposer des améliorations,
            suggérer des changements et faire avancer SNS Security.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              href="/soumettre"
              className="bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-semibold px-8 py-4 rounded-xl hover:opacity-90 active:scale-[0.98] transition-all duration-200 text-lg shadow-lg shadow-purple-900/30"
            >
              💡 Soumettre une idée
            </Link>
            <Link
              href="/idees"
              className="bg-[var(--bg-card)] text-[var(--text-primary)] font-semibold px-8 py-4 rounded-xl hover:bg-[var(--bg-hover)] active:scale-[0.98] transition-all duration-200 text-lg border border-[var(--border)]"
            >
              👀 Voir toutes les idées
            </Link>
          </div>
        </div>
      </section>

      {/* Arguments de confiance */}
      <section className="bg-[var(--bg-card)] py-16">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-2xl font-bold text-center text-[var(--text-primary)] mb-12">
            Pourquoi participer ?
          </h2>
          <div className="grid sm:grid-cols-3 gap-8">
            <div className="bg-[var(--bg-primary)] rounded-2xl p-6 border border-[var(--border)] text-center">
              <div className="text-4xl mb-4">🔒</div>
              <h3 className="font-semibold text-[var(--text-primary)] mb-2">Soumission anonyme</h3>
              <p className="text-sm text-[var(--text-secondary)]">
                Partagez vos idées sans crainte. L'anonymat est garanti par défaut.
                Votre identité reste confidentielle.
              </p>
            </div>

            <div className="bg-[var(--bg-primary)] rounded-2xl p-6 border border-[var(--border)] text-center">
              <div className="text-4xl mb-4">🗳️</div>
              <h3 className="font-semibold text-[var(--text-primary)] mb-2">Vote démocratique</h3>
              <p className="text-sm text-[var(--text-secondary)]">
                Soutenez les idées qui vous tiennent à cœur. Les propositions les plus
                populaires remontent en priorité.
              </p>
            </div>

            <div className="bg-[var(--bg-primary)] rounded-2xl p-6 border border-[var(--border)] text-center">
              <div className="text-4xl mb-4">✅</div>
              <h3 className="font-semibold text-[var(--text-primary)] mb-2">Suivi transparent</h3>
              <p className="text-sm text-[var(--text-secondary)]">
                Chaque idée est examinée et reçoit une réponse officielle du CSE.
                Suivez l'avancement en temps réel.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[var(--border)] py-8">
        <div className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <Image
            src="/logo-sns.svg"
            alt="SNS Security"
            width={80}
            height={42}
            className="h-6 w-auto opacity-50"
          />
          <span className="text-sm text-[var(--text-secondary)]">© {new Date().getFullYear()} SNS Security — Boîte à Idées CSE</span>
          <div className="flex gap-4 text-sm text-[var(--text-secondary)]">
            <Link href="/rgpd" className="hover:text-[var(--text-primary)] transition-colors">
              Politique RGPD
            </Link>
            <Link href="/admin" className="hover:text-[var(--text-primary)] transition-colors">
              Admin
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
