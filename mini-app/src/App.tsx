import * as React from 'react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { api, ApiError } from '@/lib/api'
import { init, inTelegram, onThemeChange } from '@/lib/telegram'
import { AppShell } from '@/components/app-shell'
import { Skeleton } from '@/components/ui'
import { DashboardPage } from '@/pages/dashboard'
import { TargetsPage } from '@/pages/targets'
import { ScanPage } from '@/pages/scan'
import { ChangesPage } from '@/pages/changes'
import { RulesPage } from '@/pages/rules'
import { SettingsPage } from '@/pages/settings'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        const status = (error as { status?: number } | null)?.status
        // A 401 will not fix itself by being retried, and a 403 means the
        // account is disabled or read-only: both are answers, not glitches.
        if (status === 401 || status === 403) return false
        return failureCount < 2
      },
    },
  },
})

/**
 * Shown when the app is opened outside Telegram.
 *
 * There is no login form to offer: the identity comes from a signature only
 * Telegram can produce. So this explains the requirement instead of pretending
 * a form would help.
 */
function NotInTelegram(): JSX.Element {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-6">
      <div className="card max-w-sm text-center">
        <div className="mb-3 text-4xl">📱</div>
        <h1 className="text-[17px] font-semibold">Open this from Telegram</h1>
        <p className="mt-2 text-[14px] text-hint">
          This dashboard authenticates with a signature Telegram generates, so
          it only works inside a Telegram chat.
        </p>
        <p className="mt-3 text-[13px] text-hint">
          Send <span className="font-mono">/app</span> to the bot, or tap the
          menu button in the chat.
        </p>
      </div>
    </div>
  )
}

/** Renders the page shell once the identity is known. */
function Authed(): JSX.Element {
  const me = useQuery({
    queryKey: ['me'],
    queryFn: ({ signal }) => api.me(signal),
    staleTime: Infinity,
  })

  if (me.isLoading) {
    return (
      <div className="space-y-3 p-4">
        <Skeleton className="h-10" />
        <Skeleton className="h-24" />
        <Skeleton className="h-40" />
      </div>
    )
  }

  if (me.isError) {
    const error = me.error
    const detail =
      error instanceof ApiError ? error.message : 'Could not reach the server.'

    return (
      <div className="flex min-h-screen items-center justify-center bg-bg px-6">
        <div className="card max-w-sm text-center">
          <div className="mb-3 text-4xl">
            {error instanceof ApiError && error.status === 401 ? '🔒' : '⚠️'}
          </div>
          <h1 className="text-[17px] font-semibold">Cannot open the dashboard</h1>
          <p className="mt-2 text-[14px] text-hint">{detail}</p>
          <button className="btn-quiet mt-4" onClick={() => me.refetch()}>
            Try again
          </button>
        </div>
      </div>
    )
  }

  return (
    <Routes>
      <Route element={<AppShell title="NetSentinel" />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/changes" element={<ChangesPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

/**
 * Paths are relative to basename "/app": "/targets" resolves to /app/targets.
 * Writing "/app/targets" here would double the prefix, which is the bug the
 * web panel had.
 */
function App(): JSX.Element {
  if (!inTelegram) return <NotInTelegram />

  return (
    <BrowserRouter basename="/app">
      <Routes>
        <Route path="*" element={<Authed />} />
      </Routes>
    </BrowserRouter>
  )
}

export default function Root(): JSX.Element {
  React.useEffect(() => {
    init()
    // Re-read the palette when the user switches Telegram's theme.
    return onThemeChange(() => {
      void queryClient.invalidateQueries()
    })
  }, [])

  return (
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  )
}