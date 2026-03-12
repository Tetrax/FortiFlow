// Service d'envoi d'emails via Resend
// Si RESEND_API_KEY n'est pas défini, les emails sont simulés en console

interface EmailOptions {
  to: string
  subject: string
  html: string
}

// Envoi d'un email (stub si pas de clé Resend)
export async function sendEmail({ to, subject, html }: EmailOptions): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY
  const fromEmail = process.env.FROM_EMAIL ?? 'noreply@snsbox.fr'

  // Mode stub : log en console si pas de clé
  if (!apiKey) {
    console.log('📧 [Email simulé]')
    console.log(`  À : ${to}`)
    console.log(`  Sujet : ${subject}`)
    console.log(`  Contenu : ${html.replace(/<[^>]*>/g, '').slice(0, 200)}...`)
    return true
  }

  try {
    const { Resend } = await import('resend')
    const resend = new Resend(apiKey)

    const { error } = await resend.emails.send({
      from: fromEmail,
      to,
      subject,
      html,
    })

    if (error) {
      console.error('Erreur Resend :', error)
      return false
    }

    return true
  } catch (err) {
    console.error('Erreur envoi email :', err)
    return false
  }
}

// Template : confirmation de soumission d'idée
export function buildSubmissionEmail(ideaTitle: string, ideaId: string): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000'
  return `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #2563EB;">Votre idée a bien été reçue !</h2>
      <p>Merci pour votre contribution à la boîte à idées du CSE.</p>
      <p>Votre idée <strong>"${ideaTitle}"</strong> est en cours d'examen par notre équipe.</p>
      <p>
        <a href="${appUrl}/idees/${ideaId}" style="background: #2563EB; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none;">
          Voir mon idée
        </a>
      </p>
      <p style="color: #666; font-size: 0.875rem;">
        Cet email a été envoyé automatiquement. Ne pas répondre.
      </p>
    </div>
  `
}

// Template : mise à jour du statut d'une idée
export function buildStatusUpdateEmail(
  ideaTitle: string,
  ideaId: string,
  newStatus: string,
  adminResponse?: string
): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000'

  const statusLabels: Record<string, string> = {
    NEW: 'Nouvelle',
    REVIEWING: 'En cours d\'examen',
    ACCEPTED: 'Acceptée',
    REJECTED: 'Refusée',
    DONE: 'Réalisée',
  }

  return `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #2563EB;">Mise à jour de votre idée</h2>
      <p>Le statut de votre idée <strong>"${ideaTitle}"</strong> a été mis à jour.</p>
      <p>Nouveau statut : <strong>${statusLabels[newStatus] ?? newStatus}</strong></p>
      ${adminResponse ? `<p>Réponse du CSE : <em>${adminResponse}</em></p>` : ''}
      <p>
        <a href="${appUrl}/idees/${ideaId}" style="background: #2563EB; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none;">
          Voir mon idée
        </a>
      </p>
    </div>
  `
}
