// Badge coloré selon le statut d'une idée
import { IdeaStatus } from '@prisma/client'

interface StatusBadgeProps {
  status: IdeaStatus
}

// Mapping statut → libellé et couleur Tailwind (thème sombre)
const STATUS_CONFIG: Record<IdeaStatus, { label: string; classes: string }> = {
  NEW: {
    label: 'Nouvelle',
    classes: 'bg-[#1F2937] text-[#9CA3AF] border-[#374151]',
  },
  REVIEWING: {
    label: 'En examen',
    classes: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/50',
  },
  ACCEPTED: {
    label: 'Acceptée',
    classes: 'bg-green-900/30 text-green-400 border-green-700/50',
  },
  REJECTED: {
    label: 'Refusée',
    classes: 'bg-red-900/30 text-red-400 border-red-700/50',
  },
  DONE: {
    label: 'Réalisée',
    classes: 'bg-purple-900/30 text-purple-400 border-purple-700/50',
  },
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const config = STATUS_CONFIG[status]

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${config.classes}`}
    >
      {config.label}
    </span>
  )
}
