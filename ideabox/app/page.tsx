// Page d'accueil publique
import Link from 'next/link'

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* Barre de navigation */}
      <nav className="border-b border-[#1F2937] bg-[#111111]/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-2xl">💡</span>
            <span className="font-bold text-white">Boîte à Idées</span>
          </div>
          <div className="flex items-center gap-4">
            <Link
              href="/idees"
              className="text-sm text-[#9CA3AF] hover:text-white font-medium transition-colors"
            >
              Les idées
            </Link>
            <Link
              href="/soumettre"
              className="text-sm bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white px-4 py-2 rounded-lg font-medium transition-opacity hover:opacity-90"
            >
              Soumettre
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-20 text-center">
        <h1 className="text-4xl sm:text-5xl font-bold text-white mb-6 leading-tight">
          Votre voix compte.{' '}
          <span className="bg-gradient-to-r from-[#6B21E8] to-[#2563EB] bg-clip-text text-transparent">
            Partagez vos idées.
          </span>
        </h1>
        <p className="text-xl text-[#9CA3AF] mb-10 max-w-2xl mx-auto">
          La boîte à idées du CSE est un espace sécurisé pour proposer des améliorations,
          suggérer des changements et faire avancer votre entreprise.
        </p>

        {/* CTA */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            href="/soumettre"
            className="bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white font-semibold px-8 py-4 rounded-xl hover:opacity-90 active:scale-[0.98] transition-all duration-200 text-lg shadow-lg shadow-purple-900/30"
          >
            💡 Soumettre une idée
          </Link>
          <Link
            href="/idees"
            className="bg-[#111111] text-white font-semibold px-8 py-4 rounded-xl hover:bg-[#1F2937] active:scale-[0.98] transition-all duration-200 text-lg border border-[#1F2937]"
          >
            👀 Voir toutes les idées
          </Link>
        </div>
      </section>

      {/* Arguments de confiance */}
      <section className="bg-[#111111] py-16">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-2xl font-bold text-center text-white mb-12">
            Pourquoi participer ?
          </h2>
          <div className="grid sm:grid-cols-3 gap-8">
            {/* Argument 1 */}
            <div className="bg-[#0A0A0A] rounded-2xl p-6 border border-[#1F2937] text-center">
              <div className="text-4xl mb-4">🔒</div>
              <h3 className="font-semibold text-white mb-2">Soumission anonyme</h3>
              <p className="text-sm text-[#9CA3AF]">
                Partagez vos idées sans crainte. L'anonymat est garanti par défaut.
                Votre identité reste confidentielle.
              </p>
            </div>

            {/* Argument 2 */}
            <div className="bg-[#0A0A0A] rounded-2xl p-6 border border-[#1F2937] text-center">
              <div className="text-4xl mb-4">🗳️</div>
              <h3 className="font-semibold text-white mb-2">Vote démocratique</h3>
              <p className="text-sm text-[#9CA3AF]">
                Soutenez les idées qui vous tiennent à cœur. Les propositions les plus
                populaires remontent en priorité.
              </p>
            </div>

            {/* Argument 3 */}
            <div className="bg-[#0A0A0A] rounded-2xl p-6 border border-[#1F2937] text-center">
              <div className="text-4xl mb-4">✅</div>
              <h3 className="font-semibold text-white mb-2">Suivi transparent</h3>
              <p className="text-sm text-[#9CA3AF]">
                Chaque idée est examinée et reçoit une réponse officielle du CSE.
                Suivez l'avancement en temps réel.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#1F2937] py-8 text-center text-sm text-[#9CA3AF]">
        <div className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>© {new Date().getFullYear()} CSE — Boîte à Idées</span>
          <div className="flex gap-4">
            <Link href="/rgpd" className="hover:text-white transition-colors">
              Politique RGPD
            </Link>
            <Link href="/admin" className="hover:text-white transition-colors">
              Admin
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
