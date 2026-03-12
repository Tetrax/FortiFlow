// Page d'accueil publique
import Link from 'next/link'
import Image from 'next/image'

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* Barre de navigation */}
      <nav className="border-b border-[#1F2937] bg-[#111111]/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Image
              src="/logo-sns.svg"
              alt="SNS Security"
              width={90}
              height={48}
              className="h-8 w-auto"
            />
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

      {/* Hero avec la panthère */}
      <section className="relative overflow-hidden">
        {/* Image panthère en arrière-plan */}
        <div className="absolute inset-0">
          <Image
            src="/panthere-sns.jpg"
            alt="SNS Security"
            fill
            className="object-cover object-center opacity-20"
            priority
          />
          {/* Dégradé par-dessus */}
          <div className="absolute inset-0 bg-gradient-to-b from-[#0A0A0A]/60 via-[#0A0A0A]/70 to-[#0A0A0A]" />
        </div>

        {/* Contenu hero */}
        <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-28 text-center">
          {/* Logo grand format */}
          <div className="flex justify-center mb-8">
            <Image
              src="/logo-sns.svg"
              alt="SNS Security"
              width={200}
              height={105}
              className="h-16 w-auto opacity-90"
            />
          </div>

          <p className="text-sm font-semibold tracking-widest text-[#9CA3AF] uppercase mb-4">
            Boîte à Idées — CSE
          </p>

          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-6 leading-tight">
            Votre voix compte.{' '}
            <span className="bg-gradient-to-r from-[#6B21E8] to-[#2563EB] bg-clip-text text-transparent">
              Partagez vos idées.
            </span>
          </h1>
          <p className="text-xl text-[#9CA3AF] mb-10 max-w-2xl mx-auto">
            Un espace sécurisé pour proposer des améliorations,
            suggérer des changements et faire avancer SNS Security.
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
        </div>
      </section>

      {/* Arguments de confiance */}
      <section className="bg-[#111111] py-16">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-2xl font-bold text-center text-white mb-12">
            Pourquoi participer ?
          </h2>
          <div className="grid sm:grid-cols-3 gap-8">
            <div className="bg-[#0A0A0A] rounded-2xl p-6 border border-[#1F2937] text-center">
              <div className="text-4xl mb-4">🔒</div>
              <h3 className="font-semibold text-white mb-2">Soumission anonyme</h3>
              <p className="text-sm text-[#9CA3AF]">
                Partagez vos idées sans crainte. L'anonymat est garanti par défaut.
                Votre identité reste confidentielle.
              </p>
            </div>

            <div className="bg-[#0A0A0A] rounded-2xl p-6 border border-[#1F2937] text-center">
              <div className="text-4xl mb-4">🗳️</div>
              <h3 className="font-semibold text-white mb-2">Vote démocratique</h3>
              <p className="text-sm text-[#9CA3AF]">
                Soutenez les idées qui vous tiennent à cœur. Les propositions les plus
                populaires remontent en priorité.
              </p>
            </div>

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
      <footer className="border-t border-[#1F2937] py-8">
        <div className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <Image
            src="/logo-sns.svg"
            alt="SNS Security"
            width={80}
            height={42}
            className="h-6 w-auto opacity-50"
          />
          <span className="text-sm text-[#9CA3AF]">© {new Date().getFullYear()} SNS Security — Boîte à Idées CSE</span>
          <div className="flex gap-4 text-sm text-[#9CA3AF]">
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
