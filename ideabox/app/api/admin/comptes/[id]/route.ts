import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { auth } from '@/lib/auth'

interface RouteParams {
  params: Promise<{ id: string }>
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
