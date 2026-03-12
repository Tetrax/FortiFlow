'use client'
import { signOut } from 'next-auth/react'
import Link from 'next/link'
import Image from 'next/image'
import { usePathname } from 'next/navigation'
import ThemeToggle from './ThemeToggle'

interface AdminLayoutProps {
  children: React.ReactNode
  adminName?: string
}

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
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <nav className="bg-[var(--bg-card)] border-b border-[var(--border)] sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
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

            <div className="hidden sm:flex items-center gap-1">
              {NAV_ITEMS.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive(item.href, item.exact)
                      ? 'bg-[var(--bg-accent)] text-[var(--text-on-accent)]'
                      : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </div>

            <div className="flex items-center gap-3">
              {adminName && (
                <span className="text-sm text-[var(--text-secondary)] hidden sm:block">
                  👤 {adminName}
                </span>
              )}
              <ThemeToggle />
              <button
                onClick={() => signOut({ callbackUrl: '/admin/login' })}
                className="text-sm text-red-500 hover:text-red-400 font-medium"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>

        <div className="sm:hidden border-t border-[var(--border)] flex">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`flex-1 text-center py-2 text-xs font-medium transition-colors ${
                isActive(item.href, item.exact)
                  ? 'text-[#6B21E8] border-b-2 border-[#6B21E8]'
                  : 'text-[var(--text-secondary)]'
              }`}
            >
              {item.label}
            </Link>
          ))}
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      <footer className="border-t border-[var(--border)] bg-[var(--bg-card)] mt-8 py-4">
        <div className="max-w-6xl mx-auto px-4 text-center text-xs text-[var(--text-secondary)]">
          <Link href="/" className="hover:text-[var(--text-primary)] hover:underline transition-colors">
            ← Voir le site public
          </Link>
        </div>
      </footer>
    </div>
  )
}
