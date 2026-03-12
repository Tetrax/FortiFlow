// Page RGPD - Politique de protection des données
import Link from 'next/link'

export default function RgpdPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* Navigation */}
      <nav className="bg-[#111111] border-b border-[#1F2937]">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center gap-2 text-sm text-[#9CA3AF]">
          <Link href="/" className="hover:text-[#6B21E8] transition-colors">Accueil</Link>
          <span>›</span>
          <span className="text-white">Politique RGPD</span>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <article className="bg-[#111111] rounded-2xl border border-[#1F2937] shadow-sm p-6 sm:p-10 max-w-none">
          <h1 className="text-2xl font-bold text-white mb-2">🔒 Politique de protection des données (RGPD)</h1>
          <p className="text-sm text-[#9CA3AF] mb-8">Dernière mise à jour : {new Date().toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })}</p>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">1. Responsable du traitement</h2>
          <p className="text-[#9CA3AF]">
            Le Comité Social et Économique (CSE) de l'entreprise est responsable du traitement
            des données collectées via cette application « Boîte à Idées ».
          </p>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">2. Données collectées</h2>
          <p className="text-[#9CA3AF]">Dans le cadre de la soumission d'une idée, nous collectons :</p>
          <ul className="list-disc list-inside text-[#9CA3AF] space-y-1 mt-2">
            <li>Le titre et la description de votre idée</li>
            <li>La catégorie choisie</li>
            <li>Votre nom et email <strong className="text-white">(uniquement si vous choisissez de ne pas être anonyme)</strong></li>
            <li>Un token anonymisé pour les votes (hash de votre IP + navigateur)</li>
          </ul>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">3. Finalité du traitement</h2>
          <p className="text-[#9CA3AF]">Vos données sont utilisées pour :</p>
          <ul className="list-disc list-inside text-[#9CA3AF] space-y-1 mt-2">
            <li>Afficher votre idée sur le mur des idées (sous pseudonyme ou nom si non anonyme)</li>
            <li>Vous notifier des mises à jour de statut (si email fourni)</li>
            <li>Prévenir les votes multiples (token technique, non nominal)</li>
          </ul>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">4. Anonymat par défaut</h2>
          <p className="text-[#9CA3AF]">
            Par défaut, toutes les idées sont soumises anonymement. Si vous choisissez de fournir
            votre identité, votre nom sera affiché publiquement mais votre adresse email ne sera
            jamais publiée. Elle n'est utilisée que pour vous envoyer des notifications.
          </p>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">5. Durée de conservation</h2>
          <p className="text-[#9CA3AF]">
            Les idées et les données associées sont conservées pendant toute la durée de vie de
            la boîte à idées, et jusqu'à 3 ans après sa clôture.
          </p>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">6. Vos droits</h2>
          <p className="text-[#9CA3AF]">Conformément au RGPD, vous disposez des droits suivants :</p>
          <ul className="list-disc list-inside text-[#9CA3AF] space-y-1 mt-2">
            <li><strong className="text-white">Droit d'accès</strong> : consulter vos données</li>
            <li><strong className="text-white">Droit de rectification</strong> : corriger vos données</li>
            <li><strong className="text-white">Droit à l'effacement</strong> : demander la suppression</li>
            <li><strong className="text-white">Droit d'opposition</strong> : vous opposer au traitement</li>
          </ul>
          <p className="text-[#9CA3AF] mt-3">
            Pour exercer vos droits, contactez le CSE via les voies habituelles.
          </p>

          <h2 className="text-lg font-semibold text-white mt-8 mb-3">7. Sécurité</h2>
          <p className="text-[#9CA3AF]">
            Les données sont stockées sur des serveurs sécurisés. Les mots de passe
            administrateurs sont hachés avec bcrypt. Les tokens de vote ne permettent
            pas d'identifier directement un individu.
          </p>

          <div className="mt-10 pt-6 border-t border-[#1F2937]">
            <Link href="/" className="text-sm text-[#6B21E8] hover:underline transition-colors">
              ← Retour à l'accueil
            </Link>
          </div>
        </article>
      </main>
    </div>
  )
}
