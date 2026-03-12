// Layout racine de l'application
import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Boîte à Idées CSE',
  description: 'Proposez vos idées pour améliorer votre entreprise. Votre voix compte !',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="fr">
      <body className="antialiased bg-[#0A0A0A] text-white">
        {children}
      </body>
    </html>
  )
}
