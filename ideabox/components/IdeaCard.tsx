// Carte d'affichage d'une idée dans le mur des idées
import Link from 'next/link'
import { IdeaStatus } from '@prisma/client'
import StatusBadge from './StatusBadge'

export interface IdeaCardProps {
  id: string
  title: string
  description: string
  status: IdeaStatus
  votesCount: number
  categoryName: string
  categoryIcon: string
  isAnonymous: boolean
  authorName?: string | null
  createdAt: string | Date
}

export default function IdeaCard({
  id,
  title,
  description,
  status,
  votesCount,
  categoryName,
  categoryIcon,
  isAnonymous,
  authorName,
  createdAt,
}: IdeaCardProps) {
  // Tronquer la description si trop longue
  const shortDesc =
    description.length > 150 ? description.slice(0, 150) + '…' : description

  const date = new Date(createdAt).toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })

  return (
    <Link href={`/idees/${id}`} className="block group">
      <article className="bg-[#111111] rounded-xl border border-[#1F2937] p-5 hover:border-[#6B21E8] hover:shadow-lg hover:shadow-purple-900/20 transition-all duration-200">
        {/* En-tête : catégorie + statut */}
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm text-[#9CA3AF]">
            {categoryIcon} {categoryName}
          </span>
          <StatusBadge status={status} />
        </div>

        {/* Titre */}
        <h3 className="font-semibold text-white group-hover:text-[#6B21E8] transition-colors mb-2 line-clamp-2">
          {title}
        </h3>

        {/* Description courte */}
        <p className="text-sm text-[#9CA3AF] mb-4 line-clamp-3">{shortDesc}</p>

        {/* Pied : auteur + votes + date */}
        <div className="flex items-center justify-between text-xs text-[#9CA3AF]">
          <span>
            {isAnonymous ? '🙈 Anonyme' : `👤 ${authorName ?? 'Inconnu'}`}
          </span>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              👍 <span className="font-medium text-white">{votesCount}</span>
            </span>
            <span>{date}</span>
          </div>
        </div>
      </article>
    </Link>
  )
}
