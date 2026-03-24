// Layout racine de l'application
import type { Metadata } from 'next'
import './globals.css'
import { Providers } from './providers'

export const metadata: Metadata = {
  title: 'SNS Security — Boîte à Idées CSE',
  description: 'La boîte à idées du CSE SNS Security. Proposez vos idées pour améliorer votre entreprise.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="fr" suppressHydrationWarning>
      <body className="antialiased bg-[var(--bg-primary)] text-[var(--text-primary)]">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  )
}
