// API : voter pour une idée (POST)
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { generateVoterToken, getClientIp } from '@/lib/votes'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST : enregistrer un vote
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: ideaId } = await params

    // Vérifier que l'idée existe et est visible
    const idea = await prisma.idea.findFirst({
      where: { id: ideaId, isVisible: true },
    })

    if (!idea) {
      return NextResponse.json({ error: 'Idée introuvable.' }, { status: 404 })
    }

    // Générer le token de vote (IP + UserAgent + date)
    const ip = getClientIp(request)
    const userAgent = request.headers.get('user-agent') ?? 'unknown'
    const voterToken = generateVoterToken(ip, userAgent)

    // Tenter d'insérer le vote
    try {
      await prisma.$transaction([
        prisma.vote.create({
          data: { ideaId, voterToken },
        }),
        prisma.idea.update({
          where: { id: ideaId },
          data: { votesCount: { increment: 1 } },
        }),
      ])

      return NextResponse.json({ success: true })
    } catch (err) {
      // Contrainte unique violée → déjà voté
      const e = err as { code?: string }
      if (e.code === 'P2002') {
        return NextResponse.json(
          { error: 'Vous avez déjà voté pour cette idée aujourd\'hui.' },
          { status: 409 }
        )
      }
      throw err
    }
  } catch (error) {
    console.error('Erreur POST /api/ideas/[id]/vote :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de l\'enregistrement du vote.' },
      { status: 500 }
    )
  }
}
