// Garde-fou anti-spam : limite les soumissions d'idées par IP
// Max 5 idées par IP sur une fenêtre glissante de 24h (en mémoire)

const MAX_SUBMISSIONS = 10
const WINDOW_MS = 24 * 60 * 60 * 1000 // 24h

// Map IP → timestamps des soumissions dans la fenêtre courante
const submissionsMap = new Map<string, number[]>()

/**
 * Vérifie et enregistre une tentative de soumission.
 * Retourne un message d'erreur si la limite est atteinte, null sinon.
 */
export function checkRateLimit(ip: string): string | null {
  const now = Date.now()
  const windowStart = now - WINDOW_MS

  // Récupère uniquement les soumissions dans la fenêtre active
  const recent = (submissionsMap.get(ip) ?? []).filter((t) => t > windowStart)

  if (recent.length >= MAX_SUBMISSIONS) {
    return `Vous avez soumis trop d'idées aujourd'hui (maximum ${MAX_SUBMISSIONS}). Réessayez demain.`
  }

  recent.push(now)
  submissionsMap.set(ip, recent)
  return null
}

/** Extrait l'IP cliente depuis les headers Next.js */
export function getClientIp(headers: Headers): string {
  return (
    headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    headers.get('x-real-ip') ??
    'unknown'
  )
}
