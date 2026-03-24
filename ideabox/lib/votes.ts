// Gestion des tokens de vote anti-double-vote
// Token = hash(IP + UserAgent + date du jour)
import crypto from 'crypto'

// Génère un token unique par votant et par jour
// Permet d'éviter les doublons sans stocker d'identifiant personnel
export function generateVoterToken(ip: string, userAgent: string): string {
  // On hache avec la date du jour pour limiter à 1 vote par jour par machine
  const today = new Date().toISOString().split('T')[0] // YYYY-MM-DD
  const raw = `${ip}|${userAgent}|${today}`
  return crypto.createHash('sha256').update(raw).digest('hex')
}

// Extrait l'IP depuis les headers de la requête Next.js
export function getClientIp(request: Request): string {
  const headers = request.headers
  return (
    headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    headers.get('x-real-ip') ??
    'unknown'
  )
}
