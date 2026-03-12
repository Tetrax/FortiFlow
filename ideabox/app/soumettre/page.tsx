// Page de soumission d'une nouvelle idée
// Rendu dynamique car dépend de la base de données
export const dynamic = 'force-dynamic'

import Link from 'next/link'
import { prisma } from '@/lib/prisma'
import IdeaForm from '@/components/IdeaForm'

export default async function SoumettreePage() {
  // Charger les catégories actives côté serveur
  const categories = await prisma.category.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
  })

  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* Navigation */}
      <nav className="bg-[#111111] border-b border-[#1F2937]">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center gap-2 text-sm text-[#9CA3AF]">
          <Link href="/" className="hover:text-[#6B21E8] transition-colors">Accueil</Link>
          <span>›</span>
          <span className="text-white">Soumettre une idée</span>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {/* En-tête */}
        <div className="text-center mb-10">
          <h1 className="text-3xl font-bold text-white mb-3">💡 Soumettre une idée</h1>
          <p className="text-[#9CA3AF] max-w-xl mx-auto">
            Vous avez une idée pour améliorer votre entreprise ?
            Partagez-la ! Toutes les suggestions sont lues et étudiées par le CSE.
          </p>
        </div>

        {/* Formulaire */}
        <div className="bg-[#111111] rounded-2xl border border-[#1F2937] shadow-sm p-6 sm:p-8">
          <IdeaForm categories={categories} />
        </div>

        {/* Assurance confidentialité */}
        <div className="mt-6 bg-[#1e1040] border border-[#6B21E8]/30 rounded-xl p-4 text-sm text-purple-300 flex items-start gap-3">
          <span className="text-xl shrink-0">🔒</span>
          <p>
            <strong className="text-white">Votre confidentialité est protégée.</strong> Par défaut, votre idée est
            soumise anonymement. Aucune information personnelle n'est rendue publique sans
            votre accord. Consultez notre{' '}
            <Link href="/rgpd" className="underline hover:text-white transition-colors">
              politique RGPD
            </Link>
            .
          </p>
        </div>
      </main>
    </div>
  )
}
