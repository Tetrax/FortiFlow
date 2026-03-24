import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { auth } from '@/lib/auth'
import bcrypt from 'bcryptjs'
import { z } from 'zod'

interface RouteParams {
  params: Promise<{ id: string }>
}

const patchSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8, 'Le mot de passe doit faire au moins 8 caractères'),
})

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const session = await auth()
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Non autorisé.' }, { status: 401 })
  }

  const { id } = await params

  // Un utilisateur ne peut changer que son propre mot de passe
  if (id !== session.user.id) {
    return NextResponse.json({ error: 'Non autorisé.' }, { status: 403 })
  }

  const body: unknown = await request.json()
  const parsed = patchSchema.safeParse(body)
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? 'Données invalides.' }, { status: 400 })
  }

  const { currentPassword, newPassword } = parsed.data

  const admin = await prisma.admin.findUnique({ where: { id } })
  if (!admin) {
    return NextResponse.json({ error: 'Compte introuvable.' }, { status: 404 })
  }

  const isValid = await bcrypt.compare(currentPassword, admin.passwordHash)
  if (!isValid) {
    return NextResponse.json({ error: 'Mot de passe actuel incorrect.' }, { status: 400 })
  }

  const passwordHash = await bcrypt.hash(newPassword, 12)
  await prisma.admin.update({ where: { id }, data: { passwordHash } })

  return NextResponse.json({ ok: true })
}

export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  const session = await auth()
  if (!session?.user?.id || session.user.role !== 'ADMIN') {
    return NextResponse.json({ error: 'Non autorisé.' }, { status: 403 })
  }

  const { id } = await params

  if (id === session.user.id) {
    return NextResponse.json({ error: 'Vous ne pouvez pas supprimer votre propre compte.' }, { status: 400 })
  }

  const admin = await prisma.admin.findUnique({ where: { id } })
  if (!admin) {
    return NextResponse.json({ error: 'Compte introuvable.' }, { status: 404 })
  }

  const adminCount = await prisma.admin.count({ where: { role: 'ADMIN' } })
  if (admin.role === 'ADMIN' && adminCount <= 1) {
    return NextResponse.json({ error: 'Impossible de supprimer le dernier compte administrateur.' }, { status: 400 })
  }

  await prisma.admin.delete({ where: { id } })
  return NextResponse.json({ ok: true })
}
