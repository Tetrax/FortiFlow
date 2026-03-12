'use client'
// Layout commun pour les pages d'administration
import { signOut } from 'next-auth/react'
import Link from 'next/link'
import Image from 'next/image'
import { usePathname } from 'next/navigation'

interface AdminLayoutProps {
  children: React.ReactNode
  adminName?: string
}

// Navigation admin
const NAV_ITEMS = [
  { href: '/admin', label: '📊 Tableau de bord', exact: true },
  { href: '/admin/idees', label: '💡 Idées', exact: false },
]

export default function AdminLayout({ children, adminName }: AdminLayoutProps) {
  const pathname = usePathname()

  function isActive(href: string, exact: boolean) {
    if (exact) return pathname === href
    return pathname.startsWith(href)
  }

  return (
    <div className="min-h-screen bg-[#0A0A0A]">
      {/* Barre de navigation admin */}
      <nav className="bg-[#111111] border-b border-[#1F2937] sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo / titre */}
            <div className="flex items-center gap-3">
              <Image
                src="/logo-sns.svg"
                alt="SNS Security"
                width={80}
                height={42}
                className="h-7 w-auto"
              />
              <span className="bg-gradient-to-r from-[#6B21E8] to-[#2563EB] bg-clip-text text-transparent font-semibold text-sm">
                Admin CSE
              </span>
            </div>

            {/* Liens de navigation */}
            <div className="hidden sm:flex items-center gap-1">
              {NAV_ITEMS.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive(item.href, item.exact)
                      ? 'bg-[#1e1040] text-purple-300'
                      : 'text-[#9CA3AF] hover:bg-[#1F2937] hover:text-white'
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </div>

            {/* Utilisateur + déconnexion */}
            <div className="flex items-center gap-3">
              {adminName && (
                <span className="text-sm text-[#9CA3AF] hidden sm:block">
                  👤 {adminName}
                </span>
              )}
              <button
                onClick={() => signOut({ callbackUrl: '/admin/login' })}
                className="text-sm text-red-400 hover:text-red-300 font-medium"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>

        {/* Navigation mobile */}
        <div className="sm:hidden border-t border-[#1F2937] flex">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`flex-1 text-center py-2 text-xs font-medium transition-colors ${
                isActive(item.href, item.exact)
                  ? 'text-[#6B21E8] border-b-2 border-[#6B21E8]'
                  : 'text-[#9CA3AF]'
              }`}
            >
              {item.label}
            </Link>
          ))}
        </div>
      </nav>

      {/* Contenu principal */}
      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Lien vers la partie publique */}
      <footer className="border-t border-[#1F2937] bg-[#111111] mt-8 py-4">
        <div className="max-w-6xl mx-auto px-4 text-center text-xs text-[#9CA3AF]">
          <Link href="/" className="hover:text-white hover:underline transition-colors">
            ← Voir le site public
          </Link>
        </div>
      </footer>
    </div>
  )
}
