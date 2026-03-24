// API : détail d'une idée par son identifiant
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET : récupérer une idée publique par son ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const idea = await prisma.idea.findFirst({
      where: { id, isVisible: true },
      include: {
        category: { select: { name: true, icon: true } },
      },
    })

    if (!idea) {
      return NextResponse.json({ error: 'Idée introuvable.' }, { status: 404 })
    }

    // Masquer les infos personnelles pour les idées anonymes
    return NextResponse.json({
      ...idea,
      authorName: idea.isAnonymous ? null : idea.authorName,
      authorEmail: null, // Jamais exposé publiquement
    })
  } catch (error) {
    console.error('Erreur GET /api/ideas/[id] :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de la récupération de l\'idée.' },
      { status: 500 }
    )
  }
}
