// Garde-fou anti-spam : limite les soumissions par IP, stocké en base
import { prisma } from './prisma'

const MAX_SUBMISSIONS = 10
const WINDOW_MS = 24 * 60 * 60 * 1000 // 24h

export async function checkRateLimit(ip: string): Promise<string | null> {
  const windowStart = new Date(Date.now() - WINDOW_MS)

  // Nettoyage des anciennes entrées au passage
  await prisma.rateLimit.deleteMany({
    where: { submittedAt: { lt: windowStart } },
  })

  const count = await prisma.rateLimit.count({
    where: { ip, submittedAt: { gte: windowStart } },
  })

  if (count >= MAX_SUBMISSIONS) {
    return `Vous avez soumis trop d'idées aujourd'hui (maximum ${MAX_SUBMISSIONS}). Réessayez demain.`
  }

  await prisma.rateLimit.create({ data: { ip } })
  return null
}

export function getClientIp(headers: Headers): string {
  return (
    headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    headers.get('x-real-ip') ??
    'unknown'
  )
}
