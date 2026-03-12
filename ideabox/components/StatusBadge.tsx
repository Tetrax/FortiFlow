// Badge coloré selon le statut d'une idée
import { IdeaStatus } from '@prisma/client'

interface StatusBadgeProps {
  status: IdeaStatus
}

const STATUS_CONFIG: Record<IdeaStatus, { label: string; classes: string }> = {
  NEW: {
    label: 'Nouvelle',
    classes: 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-[#1F2937] dark:text-[#9CA3AF] dark:border-[#374151]',
  },
  REVIEWING: {
    label: 'En examen',
    classes: 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-700/50',
  },
  ACCEPTED: {
    label: 'Acceptée',
    classes: 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-400 dark:border-green-700/50',
  },
  REJECTED: {
    label: 'Refusée',
    classes: 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-700/50',
  },
  DONE: {
    label: 'Réalisée',
    classes: 'bg-purple-100 text-purple-800 border-purple-200 dark:bg-purple-900/30 dark:text-purple-400 dark:border-purple-700/50',
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
