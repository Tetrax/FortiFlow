// Seed : catégories par défaut + admin de démonstration
import { PrismaClient, AdminRole } from '@prisma/client'
import bcrypt from 'bcryptjs'

const prisma = new PrismaClient()

async function main() {
  console.log('🌱 Démarrage du seed...')

  // Catégories par défaut
  const categories = [
    { name: 'Organisation & RH', icon: '🏢' },
    { name: 'Conditions de travail', icon: '💼' },
    { name: 'RSE & Développement durable', icon: '🌿' },
    { name: "Vie d'entreprise & CSE", icon: '🎉' },
    { name: 'Outils & Digital', icon: '💻' },
    { name: 'Santé & Bien-être', icon: '🏥' },
    { name: 'Communication interne', icon: '📣' },
    { name: 'Autre', icon: '💡' },
  ]

  for (const cat of categories) {
    // Chercher par nom, puis créer ou ignorer
    const existing = await prisma.category.findFirst({ where: { name: cat.name } })
    if (!existing) {
      await prisma.category.create({ data: cat })
    }
  }
  console.log(`✅ ${categories.length} catégories prêtes`)

  // Admin de démonstration
  const passwordHash = await bcrypt.hash('Admin1234!', 12)

  await prisma.admin.upsert({
    where: { email: 'admin@snsbox.fr' },
    update: {},
    create: {
      email: 'admin@snsbox.fr',
      name: 'Administrateur',
      role: AdminRole.ADMIN,
      passwordHash,
    },
  })
  console.log('✅ Admin démo prêt : admin@snsbox.fr / Admin1234!')

  console.log('🎉 Seed terminé !')
}

main()
  .catch((e) => {
    console.error('❌ Erreur seed :', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
