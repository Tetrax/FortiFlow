import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { auth } from '@/lib/auth'
import { z } from 'zod'
import bcrypt from 'bcryptjs'

const createAdminSchema = z.object({
  username: z.string().min(3, 'Nom d\'utilisateur trop court (3 caractères min)').max(50).regex(/^[a-zA-Z0-9_-]+$/, 'Caractères autorisés : lettres, chiffres, - et _'),
  email: z.string().email('Email invalide').optional().or(z.literal('')),
  name: z.string().min(2, 'Nom trop court').max(100),
  role: z.enum(['MODERATOR', 'ADMIN']),
  password: z.string().min(8, 'Mot de passe trop court (8 caractères min)').max(100),
})

export async function GET() {
  const session = await auth()
  if (!session?.user?.id || session.user.role !== 'ADMIN') {
    return NextResponse.json({ error: 'Non autorisé.' }, { status: 403 })
  }

  const admins = await prisma.admin.findMany({
    select: { id: true, username: true, email: true, name: true, role: true, createdAt: true },
    orderBy: { createdAt: 'asc' },
  })

  return NextResponse.json(admins)
}

export async function POST(request: NextRequest) {
  const session = await auth()
  if (!session?.user?.id || session.user.role !== 'ADMIN') {
    return NextResponse.json({ error: 'Non autorisé.' }, { status: 403 })
  }

  const body: unknown = await request.json()
  const parsed = createAdminSchema.safeParse(body)
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message ?? 'Données invalides.' },
      { status: 400 }
    )
  }

  const { username, email, name, role, password } = parsed.data

  const existing = await prisma.admin.findUnique({ where: { username } })
  if (existing) {
    return NextResponse.json({ error: 'Ce nom d\'utilisateur est déjà utilisé.' }, { status: 409 })
  }

  const passwordHash = await bcrypt.hash(password, 10)
  const admin = await prisma.admin.create({
    data: { username, email: email || null, name, role, passwordHash },
    select: { id: true, username: true, email: true, name: true, role: true, createdAt: true },
  })

  return NextResponse.json(admin, { status: 201 })
}
