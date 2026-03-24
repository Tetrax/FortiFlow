// API : liste des idées (GET) et soumission d'une nouvelle idée (POST)
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'
import { sendEmail, buildSubmissionEmail, buildModeratorNotificationEmail } from '@/lib/email'
import { IdeaStatus } from '@prisma/client'
import { checkModeration } from '@/lib/moderation'
import { checkRateLimit, getClientIp } from '@/lib/rateLimit'

// Schéma de validation pour la soumission d'une idée
const createIdeaSchema = z.object({
  title: z.string().min(5, 'Le titre doit faire au moins 5 caractères').max(150),
  description: z.string().min(20, 'La description doit faire au moins 20 caractères').max(2000),
  categoryId: z.string().cuid('Catégorie invalide'),
  isAnonymous: z.boolean().default(true),
  authorName: z.string().max(100).optional(),
  authorEmail: z.string().email('Email invalide').optional().or(z.literal('')),
})

// GET : liste des idées visibles avec filtres optionnels
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const categoryId = searchParams.get('categoryId')
    const status = searchParams.get('status') as IdeaStatus | null
    const page = Math.max(1, parseInt(searchParams.get('page') ?? '1', 10))
    const limit = Math.min(50, Math.max(1, parseInt(searchParams.get('limit') ?? '12', 10)))
    const skip = (page - 1) * limit

    // Filtres dynamiques
    const where = {
      isVisible: true,
      ...(categoryId ? { categoryId } : {}),
      ...(status && Object.values(IdeaStatus).includes(status) ? { status } : {}),
    }

    const [ideas, total] = await Promise.all([
      prisma.idea.findMany({
        where,
        include: {
          category: { select: { name: true, icon: true } },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.idea.count({ where }),
    ])

    // Masquer les infos personnelles pour les idées anonymes
    const sanitizedIdeas = ideas.map((idea) => ({
      ...idea,
      authorName: idea.isAnonymous ? null : idea.authorName,
      authorEmail: null, // Ne jamais exposer l'email en public
    }))

    return NextResponse.json({
      ideas: sanitizedIdeas,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    })
  } catch (error) {
    console.error('Erreur GET /api/ideas :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de la récupération des idées.' },
      { status: 500 }
    )
  }
}

// POST : soumettre une nouvelle idée
export async function POST(request: NextRequest) {
  try {
    const body: unknown = await request.json()
    const parsed = createIdeaSchema.safeParse(body)

    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues[0]?.message ?? 'Données invalides.' },
        { status: 400 }
      )
    }

    const data = parsed.data

    // Garde-fou 1 : limite anti-spam par IP
    const ip = getClientIp(request.headers)
    const rateLimitError = checkRateLimit(ip)
    if (rateLimitError) {
      return NextResponse.json({ error: rateLimitError }, { status: 429 })
    }

    // Garde-fou 2 : modération du contenu
    const moderationError = checkModeration(data.title, data.description)
    if (moderationError) {
      return NextResponse.json({ error: moderationError }, { status: 422 })
    }

    // Garde-fou 3 : détection de doublon (même titre dans les 30 derniers jours)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    const duplicate = await prisma.idea.findFirst({
      where: {
        title: data.title,
        createdAt: { gte: thirtyDaysAgo },
      },
    })
    if (duplicate) {
      return NextResponse.json(
        { error: 'Une idée avec ce titre a déjà été soumise récemment. Essayez un titre différent.' },
        { status: 409 }
      )
    }

    // Vérifier que la catégorie existe et est active
    const category = await prisma.category.findFirst({
      where: { id: data.categoryId, isActive: true },
    })

    if (!category) {
      return NextResponse.json({ error: 'Catégorie introuvable.' }, { status: 404 })
    }

    // Créer l'idée
    const idea = await prisma.idea.create({
      data: {
        title: data.title,
        description: data.description,
        categoryId: data.categoryId,
        isAnonymous: data.isAnonymous,
        authorName: data.isAnonymous ? null : data.authorName ?? null,
        authorEmail: data.isAnonymous ? null : (data.authorEmail || null),
      },
    })

    // Envoyer un email de confirmation si l'auteur a fourni son email
    if (!data.isAnonymous && data.authorEmail) {
      await sendEmail({
        to: data.authorEmail,
        subject: '✅ Votre idée a bien été reçue',
        html: buildSubmissionEmail(idea.title, idea.id),
      })
    }

    // Notifier tous les modérateurs / admins CSE de la nouvelle idée
    const moderators = await prisma.admin.findMany({
      where: { email: { not: null } },
      select: { email: true },
    })
    const notifHtml = buildModeratorNotificationEmail(
      idea.title,
      idea.id,
      category.name,
      data.isAnonymous,
      data.authorName
    )
    await Promise.all(
      moderators
        .filter((m): m is { email: string } => m.email !== null)
        .map((m) =>
          sendEmail({
            to: m.email,
            subject: '💡 Nouvelle idée soumise — modération requise',
            html: notifHtml,
          })
        )
    )

    return NextResponse.json({ id: idea.id }, { status: 201 })
  } catch (error) {
    console.error('Erreur POST /api/ideas :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de la soumission de votre idée.' },
      { status: 500 }
    )
  }
}
