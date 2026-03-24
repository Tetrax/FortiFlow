// Service d'envoi d'emails via Resend
// Si RESEND_API_KEY n'est pas défini, les emails sont simulés en console

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

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
  const safeTitle = escapeHtml(ideaTitle)
  const safeId = encodeURIComponent(ideaId)
  return `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #2563EB;">Votre idée a bien été reçue !</h2>
      <p>Merci pour votre contribution à la boîte à idées du CSE.</p>
      <p>Votre idée <strong>"${safeTitle}"</strong> est en cours d'examen par notre équipe.</p>
      <p>
        <a href="${appUrl}/idees/${safeId}" style="background: #2563EB; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none;">
          Voir mon idée
        </a>
      </p>
      <p style="color: #666; font-size: 0.875rem;">
        Cet email a été envoyé automatiquement. Ne pas répondre.
      </p>
    </div>
  `
}

// Template : notification aux modérateurs CSE pour une nouvelle idée
export function buildModeratorNotificationEmail(
  ideaTitle: string,
  ideaId: string,
  categoryName: string,
  isAnonymous: boolean,
  authorName?: string | null
): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000'
  const safeTitle = escapeHtml(ideaTitle)
  const safeId = encodeURIComponent(ideaId)
  const safeCategory = escapeHtml(categoryName)
  const safeAuthor = isAnonymous ? 'Anonyme' : escapeHtml(authorName ?? 'Inconnu')

  return `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #2563EB;">💡 Nouvelle idée soumise</h2>
      <p>Une nouvelle idée vient d'être déposée dans la boîte à idées CSE et attend votre modération.</p>
      <table style="width:100%; border-collapse:collapse; margin: 16px 0;">
        <tr>
          <td style="padding: 8px 12px; background:#f3f4f6; font-weight:600; width:120px;">Titre</td>
          <td style="padding: 8px 12px; border-bottom:1px solid #e5e7eb;">${safeTitle}</td>
        </tr>
        <tr>
          <td style="padding: 8px 12px; background:#f3f4f6; font-weight:600;">Catégorie</td>
          <td style="padding: 8px 12px; border-bottom:1px solid #e5e7eb;">${safeCategory}</td>
        </tr>
        <tr>
          <td style="padding: 8px 12px; background:#f3f4f6; font-weight:600;">Auteur</td>
          <td style="padding: 8px 12px;">${safeAuthor}</td>
        </tr>
      </table>
      <p>
        <a href="${appUrl}/admin/idees/${safeId}" style="background: #2563EB; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none;">
          Modérer cette idée
        </a>
      </p>
      <p style="color: #666; font-size: 0.875rem; margin-top: 24px;">
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

  const safeTitle = escapeHtml(ideaTitle)
  const safeId = encodeURIComponent(ideaId)
  const safeStatus = escapeHtml(statusLabels[newStatus] ?? newStatus)
  const safeResponse = adminResponse ? escapeHtml(adminResponse) : null

  return `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #2563EB;">Mise à jour de votre idée</h2>
      <p>Le statut de votre idée <strong>"${safeTitle}"</strong> a été mis à jour.</p>
      <p>Nouveau statut : <strong>${safeStatus}</strong></p>
      ${safeResponse ? `<p>Réponse du CSE : <em>${safeResponse}</em></p>` : ''}
      <p>
        <a href="${appUrl}/idees/${safeId}" style="background: #2563EB; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none;">
          Voir mon idée
        </a>
      </p>
    </div>
  `
}
