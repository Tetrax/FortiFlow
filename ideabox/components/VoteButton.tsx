'use client'
// Bouton de vote pour une idée
import { useState } from 'react'

interface VoteButtonProps {
  ideaId: string
  initialCount: number
}

export default function VoteButton({ ideaId, initialCount }: VoteButtonProps) {
  const [count, setCount] = useState(initialCount)
  const [voted, setVoted] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleVote() {
    if (voted || loading) return

    setLoading(true)
    setError(null)

    try {
      const res = await fetch(`/api/ideas/${ideaId}/vote`, {
        method: 'POST',
      })

      if (res.ok) {
        setCount((c) => c + 1)
        setVoted(true)
      } else if (res.status === 409) {
        setVoted(true)
        setError('Vous avez déjà voté pour cette idée aujourd\'hui.')
      } else {
        setError('Impossible de voter. Réessayez plus tard.')
      }
    } catch {
      setError('Erreur réseau. Réessayez.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col items-center gap-1">
      <button
        onClick={handleVote}
        disabled={voted || loading}
        className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-all duration-200 ${
          voted
            ? 'bg-purple-100 text-purple-700 cursor-default dark:bg-[#1e1040] dark:text-purple-300'
            : 'bg-gradient-to-r from-[#6B21E8] to-[#2563EB] text-white hover:opacity-90 active:scale-95'
        } disabled:opacity-70`}
        aria-label={`Voter pour cette idée (${count} votes)`}
      >
        {loading ? (
          <span className="animate-spin">⏳</span>
        ) : voted ? (
          '✅'
        ) : (
          '👍'
        )}
        <span>{count} vote{count !== 1 ? 's' : ''}</span>
      </button>

      {error && (
        <p className="text-xs text-red-500 dark:text-red-400 mt-1">{error}</p>
      )}
    </div>
  )
}
