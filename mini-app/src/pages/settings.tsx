import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { close, haptic, toast } from '@/lib/telegram'
import { Segmented, Skeleton, Toggle } from '@/components/ui'

type Theme = 'auto' | 'dark' | 'light'
type Lang = 'fa' | 'en'

export function SettingsPage(): JSX.Element {
  const queryClient = useQueryClient()
  const [theme, setTheme] = React.useState<Theme>('auto')

  // The theme choice is local to this device: Telegram owns the real palette,
  // and "auto" simply means whatever the user's Telegram theme already is.
  React.useEffect(() => {
    try {
      const stored = window.localStorage.getItem('ns-miniapp-theme')
      if (stored === 'dark' || stored === 'light' || stored === 'auto') {
        setTheme(stored)
      }
    } catch {
      /* private mode */
    }
  }, [])

  function applyTheme(next: Theme): void {
    setTheme(next)
    try {
      window.localStorage.setItem('ns-miniapp-theme', next)
    } catch {
      /* private mode: the choice just does not persist */
    }
    haptic()
    const root = document.documentElement
    if (next === 'auto') {
      root.removeAttribute('data-color-scheme')
    } else {
      root.setAttribute('data-color-scheme', next)
    }
  }

  const me = useQuery({
    queryKey: ['me'],
    queryFn: ({ signal }) => api.me(signal),
    staleTime: Infinity,
  })

  const save = useMutation({
    mutationFn: (body: { language?: string; notifications_enabled?: boolean }) =>
      api.updateSettings(body),
    onSuccess: () => {
      haptic('success')
      toast('Saved')
      void queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (error) => {
      haptic('error')
      toast((error as Error).message)
    },
  })

  if (me.isError) {
    return (
      <div className="card p-4 text-[13px] text-hint">
        Could not load your profile. Open the app from Telegram.
      </div>
    )
  }

  const profile = me.data
  const isOperator = profile?.role === 'operator' || profile?.role === 'admin'

  return (
    <div className="space-y-3">
      <section className="card">
        <h2 className="text-[15px] font-semibold">Profile</h2>
        {me.isLoading ? (
          <Skeleton className="mt-2 h-16" />
        ) : profile ? (
          <>
            <p className="mt-1 text-[15px]">{profile.display_name}</p>
            <p className="text-[13px] text-hint">
              {profile.username ? `@${profile.username}` : 'no username'} ·{' '}
              {profile.role}
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {profile.is_premium ? (
                <span className="rounded-full bg-warn-soft px-2 py-0.5 text-[11px] font-medium text-warn">
                  Telegram Premium
                </span>
              ) : null}
              {!isOperator ? (
                <span className="rounded-full bg-secondary px-2 py-0.5 text-[11px] text-hint">
                  read-only
                </span>
              ) : null}
            </div>
          </>
        ) : null}
      </section>

      <section className="card space-y-3">
        <h2 className="text-[15px] font-semibold">Language</h2>
        <Segmented<Lang>
          options={['fa', 'en']}
          value={(profile?.language as Lang) ?? 'fa'}
          onChange={(next) => save.mutate({ language: next })}
        />
        <p className="text-[12px] text-hint">
          Applies to the bot's replies too.
        </p>
      </section>

      <section className="card space-y-3">
        <h2 className="text-[15px] font-semibold">Appearance</h2>
        <Segmented<Theme>
          options={['auto', 'light', 'dark'] as const}
          value={theme}
          onChange={applyTheme}
        />
        <p className="text-[12px] text-hint">
          Auto follows your Telegram theme, which is also what the whole app
          already uses for its colours.
        </p>
      </section>

      <section className="card">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-[15px] font-semibold">Notifications</h2>
            <p className="text-[12px] text-hint">
              Change alerts for this account.
            </p>
          </div>
          <Toggle
            label="Notifications"
            checked={profile?.notifications_enabled ?? true}
            onChange={(next) => save.mutate({ notifications_enabled: next })}
          />
        </div>
      </section>

      <section className="card space-y-2">
        <h2 className="text-[15px] font-semibold">Export</h2>
        <button
          className="btn-quiet w-full"
          onClick={() => {
            try {
              const payload = {
                exported_at: new Date().toISOString(),
                targets: [],
                note:
                  'Target history is exported from the web panel; the bot reply is the summary.',
              }
              const blob = new Blob([JSON.stringify(payload, null, 2)], {
                type: 'application/json',
              })
              const url = URL.createObjectURL(blob)
              const anchor = document.createElement('a')
              anchor.href = url
              anchor.download = 'netsentinel-export.json'
              anchor.click()
              URL.revokeObjectURL(url)
              toast('Exported')
            } catch {
              toast('Export failed')
            }
          }}
        >
          Export my data
        </button>
      </section>

      <section className="card space-y-2">
        <h2 className="text-[15px] font-semibold">About</h2>
        <p className="text-[13px] text-hint">NetSentinel Mini App 3.0.0</p>
        <p className="text-[12px] text-hint">
          Authentication is Telegram's signed initData. There is no password
          for this app, and the server re-checks the signature on every
          request.
        </p>
        <button className="btn-quiet w-full" onClick={close}>
          Close
        </button>
      </section>
    </div>
  )
}