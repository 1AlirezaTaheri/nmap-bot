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
        navigate('/login', { replace: true })
      })
  }

  if (isLoading) return <FullScreenSpinner />

  // Not signed in, or the session went away. <Navigate> is a client-side
  // navigation, so this never reloads the page.
  if (isError || !me) return <Navigate to="/login" replace />

  return (
    <AppShell username={me.username} role={me.role} onLogout={logout} onRefresh={refresh}>
      {/* key forces a remount when the toolbar refresh button is pressed */}
      <React.Fragment key={tick}>
        <Routes>
          <Route path="/" element={<DashboardPage onRefresh={refresh} />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </React.Fragment>
    </AppShell>
  )
}

/**
 * Wires "session lost" to "go back to login", as a client-side navigation.
 *
 * It lives inside the Router because it needs `useNavigate`. The previous
 * version assigned `window.location.href`, which is a hard reload — and
 * combined with the route paths below it re-entered the shell on every pass,
 * producing a reload loop on an unauthenticated visit.
 *
 * api.ts suppresses this handler for the initial `/api/me` probe, so this only
 * fires when a session genuinely existed and was then lost.
 */
function SessionGuard(): null {
  const navigate = useNavigate()

  React.useEffect(() => {
    setUnauthorizedHandler(() => {
      queryClient.clear()
      navigate('/login', { replace: true })
    })
    return () => setUnauthorizedHandler(() => {})
  }, [navigate])

  return null
}

function App(): JSX.Element {
  const theme = useUIStore((s) => s.theme)

  return (
    // basename="/admin" means every route path and every navigation target
    // below is relative to /admin. Writing "/admin/users" here would resolve
    // to /admin/admin/users.
    <BrowserRouter basename="/admin">
      <SessionGuard />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
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
  return (
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  )
}