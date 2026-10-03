import * as React from 'react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { Toaster } from 'sonner'
import { api, setUnauthorizedHandler } from '@/lib/api'
import { useUIStore } from '@/store/ui'
import { AppShell } from '@/components/app-shell'
import { TooltipProvider } from '@/components/ui'
import { Spinner } from '@/components/feedback'
import { LoginPage } from '@/pages/login'
import { DashboardPage } from '@/pages/dashboard'
import { UsersPage } from '@/pages/users'
import { TargetsPage } from '@/pages/targets'
import { AuditPage } from '@/pages/audit'
import { SettingsPage } from '@/pages/settings'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The panel is a monitoring tool; 30s stale is plenty and keeps the
      // dashboard honest without hammering Postgres.
      staleTime: 30_000,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        // Retrying a 401 just repeats the same answer.
        const status = (error as { status?: number } | null)?.status
        if (status === 401 || status === 403) return false
        return failureCount < 2
      },
    },
  },
})

function FullScreenSpinner(): JSX.Element {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg">
      <Spinner className="h-6 w-6 text-primary" />
    </div>
  )
}

function Shell(): JSX.Element {
  const [tick, setTick] = React.useState(0)
  const navigate = useNavigate()

  const { data: me, isLoading, isError } = useQuery({
    queryKey: ['me'],
    queryFn: ({ signal }) => api.me(signal),
    // Identity only changes on sign-in/out, so never auto-refetch it.
    staleTime: Infinity,
    gcTime: Infinity,
  })

  function refresh(): void {
    setTick((value) => value + 1)
    void queryClient.invalidateQueries()
  }

  function logout(): void {
    void api
      .logout()
      .catch(() => undefined)
      .finally(() => {
        queryClient.clear()
        navigate('/admin/login', { replace: true })
      })
  }

  if (isLoading) return <FullScreenSpinner />

  // A 401 already fired the unauthorized handler. Reaching here with an
  // error means the session is unusable, so send them to login rather than
  // rendering a shell with no data.
  if (isError || !me) return <Navigate to="/admin/login" replace />

  return (
    <AppShell username={me.username} role={me.role} onLogout={logout} onRefresh={refresh}>
      {/* key forces a remount when the toolbar refresh button is pressed */}
      <React.Fragment key={tick}>
        <Routes>
          <Route path="/admin" element={<DashboardPage onRefresh={refresh} />} />
          <Route path="/admin/users" element={<UsersPage />} />
          <Route path="/admin/targets" element={<TargetsPage />} />
          <Route path="/admin/audit" element={<AuditPage />} />
          <Route path="/admin/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/admin" replace />} />
        </Routes>
      </React.Fragment>
    </AppShell>
  )
}

function App(): JSX.Element {
  const theme = useUIStore((s) => s.theme)

  return (
    <BrowserRouter basename="/admin">
      <Routes>
        <Route path="/admin/login" element={<LoginPage />} />
        <Route
          path="*"
          element={
            <TooltipProvider>
              <Shell />
            </TooltipProvider>
          }
        />
      </Routes>
      <Toaster position="bottom-right" richColors closeButton theme={theme} />
    </BrowserRouter>
  )
}

export default function Root(): JSX.Element {
  React.useEffect(() => {
    // One place wires "session expired" to "go back to login".
    setUnauthorizedHandler(() => {
      queryClient.clear()
      window.location.href = '/admin/login'
    })
  }, [])

  return (
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  )
}