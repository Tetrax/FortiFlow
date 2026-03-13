// API admin : mise à jour d'une idée (statut, réponse, visibilité)
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { auth } from '@/lib/auth'
import { z } from 'zod'
import { IdeaStatus } from '@prisma/client'
import { sendEmail, buildStatusUpdateEmail } from '@/lib/email'

interface RouteParams {
  params: Promise<{ id: string }>
}

// Schéma de validation pour le PATCH
const patchIdeaSchema = z.object({
  status: z.nativeEnum(IdeaStatus).optional(),
  adminResponse: z.string().max(1000).optional().nullable(),
  isVisible: z.boolean().optional(),
})

// PATCH : modifier le statut / réponse d'une idée (admin uniquement)
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    // Vérification de la session admin
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Non autorisé.' }, { status: 401 })
    }

    const { id: ideaId } = await params

    // Récupérer l'idée actuelle
    const existing = await prisma.idea.findUnique({ where: { id: ideaId } })
    if (!existing) {
      return NextResponse.json({ error: 'Idée introuvable.' }, { status: 404 })
    }

    // Valider le body
    const body: unknown = await request.json()
    const parsed = patchIdeaSchema.safeParse(body)

    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues[0]?.message ?? 'Données invalides.' },
        { status: 400 }
      )
    }

    const { status, adminResponse, isVisible } = parsed.data

    // Préparer les mises à jour
    const updateData = {
      ...(status !== undefined ? { status } : {}),
      ...(adminResponse !== undefined ? { adminResponse } : {}),
      ...(isVisible !== undefined ? { isVisible } : {}),
    }

    // Mettre à jour l'idée + historique si le statut change
    const [updatedIdea] = await prisma.$transaction(async (tx) => {
      const updated = await tx.idea.update({
        where: { id: ideaId },
        data: updateData,
      })

      // Enregistrer l'historique si le statut a changé
      if (status && status !== existing.status) {
        await tx.statusHistory.create({
          data: {
            ideaId,
            oldStatus: existing.status,
            newStatus: status,
            changedBy: session.user.id,
          },
        })
      }

      return [updated]
    })

    // Envoyer un email si statut changé et email connu
    if (status && status !== existing.status && existing.authorEmail) {
      await sendEmail({
        to: existing.authorEmail,
        subject: '📬 Mise à jour de votre idée',
        html: buildStatusUpdateEmail(
          existing.title,
          ideaId,
          status,
          adminResponse ?? undefined
        ),
      })
    }

    return NextResponse.json(updatedIdea)
  } catch (error) {
    console.error('Erreur PATCH /api/admin/ideas/[id] :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de la mise à jour de l\'idée.' },
      { status: 500 }
    )
  }
}

// DELETE : supprimer définitivement une idée (admin uniquement)
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Non autorisé.' }, { status: 401 })
    }

    const { id: ideaId } = await params

    const existing = await prisma.idea.findUnique({ where: { id: ideaId } })
    if (!existing) {
      return NextResponse.json({ error: 'Idée introuvable.' }, { status: 404 })
    }

    await prisma.idea.delete({ where: { id: ideaId } })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Erreur DELETE /api/admin/ideas/[id] :', error)
    return NextResponse.json(
      { error: 'Erreur serveur lors de la suppression.' },
      { status: 500 }
    )
  }
}
