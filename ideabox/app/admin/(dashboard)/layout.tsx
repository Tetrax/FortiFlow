import { auth } from '@/lib/auth'
import { redirect } from 'next/navigation'
import AdminLayout from '@/components/AdminLayout'

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth()
  if (!session?.user) redirect('/admin/login')

  return (
    <AdminLayout adminName={session.user.name ?? undefined} adminRole={session.user.role ?? undefined}>
      {children}
    </AdminLayout>
  )
}
