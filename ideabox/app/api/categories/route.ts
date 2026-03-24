// API : liste des catégories actives
import { NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function GET() {
  try {
    const categories = await prisma.category.findMany({
      where: { isActive: true },
      orderBy: { name: 'asc' },
    })

    return NextResponse.json(categories)
  } catch (error) {
    console.error('Erreur GET /api/categories :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de la récupération des catégories.' },
      { status: 500 }
    )
  }
}
