import * as React from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Play } from 'lucide-react'
import { api } from '@/lib/api'
import { haptic, toast } from '@/lib/telegram'
import { cn, elapsed, relative } from '@/lib/utils'
import { Badge, EmptyState, ErrorState, Segmented, Skeleton } from '@/components/ui'

const PROFILES = ['quick', 'service', 'deep'] as const
type Profile = (typeof PROFILES)[number]

export function ScanPage(): JSX.Element {
  const [target, setTarget] = React.useState<string>('')
  const [profile, setProfile] = React.useState<Profile>('service')

  const targets = useQuery({
    queryKey: ['targets'],
    queryFn: ({ signal }) => api.targets(signal),
  })

  const active = useQuery({
    queryKey: ['active-scan'],
    queryFn: ({ signal }) => api.activeScan(signal),
    // Poll only while something is running, and stop as soon as it is not:
    // an idle dashboard should not cost a request every two seconds.
    refetchInterval: (query) =>
      query.state.data?.scan ? 2000 : false,
  })

  const profiles = useQuery({
    queryKey: ['profiles'],
    queryFn: ({ signal }) => api.profiles(signal),
    staleTime: Infinity,
  })

  // The server advertises its profile names, but the segmented control is
  // typed to the three this build knows how to label. Narrowing rather than
  // widening the type keeps a profile added server-side from rendering as an
  // unlabelled button that cannot change the selection.
  const profileOptions = React.useMemo<Profile[]>(() => {
    const advertised = profiles.data?.profiles ?? []
    const known = PROFILES.filter((p) => advertised.includes(p))
    return known.length > 0 ? [...known] : [...PROFILES]
  }, [profiles.data])

  // Default the picker once the list arrives, and when the current pick is
  // removed by someone else.
  React.useEffect(() => {
    const names = targets.data?.targets.map((t) => t.name) ?? []
    if (names.length === 0) return
    if (!target || !names.includes(target)) setTarget(names[0] ?? '')
  }, [targets.data, target])

  // Keep the selection inside the offered set: if the server stops
  // advertising the chosen profile, the Start button would otherwise send a
  // profile the control no longer shows.
  React.useEffect(() => {
    if (!profileOptions.includes(profile)) {
      setProfile(profileOptions[0] ?? 'service')
    }
  }, [profileOptions, profile])

  const start = useMutation({
    mutationFn: () => api.startScan({ target, profile }),
    onSuccess: (result) => {
      haptic('success')
      toast(`Queued scan of ${result.target}`)
      void active.refetch()
    },
    onError: (error) => {
      haptic('error')
      toast((error as Error).message)
    },
  })

  const names = targets.data?.targets ?? []
  const running = active.data?.scan ?? null

  if (targets.isError) {
    return (
      <ErrorState
        message={(targets.error as Error).message}
        onRetry={() => void targets.refetch()}
      />
    )
  }

  return (
    <div className="space-y-4">
      <section className="card">
        <h2 className="mb-3 text-[15px] font-semibold">New scan</h2>

        {names.length === 0 ? (
          <EmptyState
            icon="🛰"
            title="No targets yet"
            description="Add one from the Targets tab first."
          />
        ) : (
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-[13px] text-hint" htmlFor="s-target">
                Target
              </label>
              <select
                id="s-target"
                className="input"
                value={target}
                onChange={(event) => {
                  haptic()
                  setTarget(event.target.value)
                }}
              >
                {names.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name} · {t.value}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <span className="mb-1 block text-[13px] text-hint">Profile</span>
              <Segmented<Profile>
                options={profileOptions}
                value={profile}
                onChange={setProfile}
              />
            </div>

            <button
              className="btn-primary mt-1"
              disabled={!target || start.isPending || running !== null}
              onClick={() => start.mutate()}
            >
              <Play className="h-4 w-4" />
              {start.isPending ? 'Queueing…' : 'Start scan'}
            </button>

            <p className="text-center text-[12px] text-hint">
              Rules, scope and the rate limit all apply here exactly as they
              do in chat.
            </p>
          </div>
        )}
      </section>

      {running ? (
        <section className="card">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-[15px] font-semibold">Scan in progress</h2>
            <Badge className="bg-info-soft text-info">{running.status}</Badge>
          </div>

          <div className="mb-2 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
            <div className="h-full w-1/3 animate-pulse rounded-full bg-info" />
          </div>

          <p className="text-[13px] text-hint">
            {running.target ?? `scan #${running.id}`} · {profile} ·{' '}
            {elapsed(running.started_at)}
          </p>
        </section>
      ) : null}

      {!running && active.isFetched && start.isSuccess ? (
        <section className="card">
          <h2 className="mb-2 text-[15px] font-semibold">Queued</h2>
          <p className="text-[13px] text-hint">
            The scan was accepted. It appears in Recent scans on the dashboard
            once it finishes.
          </p>
        </section>
      ) : null}

      {active.isLoading ? <Skeleton className="h-20" /> : null}
    </div>
  )
}

/** Result card, shown once a scan this user started has completed. */
export function ScanResult({
  scanId,
}: {
  scanId: number
}): JSX.Element {
  const scan = useQuery({
    queryKey: ['scan', scanId],
    queryFn: ({ signal }) => api.scan(scanId, signal),
  })

  if (scan.isLoading) return <Skeleton className="h-24" />
  if (scan.isError || !scan.data) return <></>

  const row = scan.data.scan
  const changed = (row.change_count ?? 0) > 0

  return (
    <section className="card">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-[15px] font-semibold">{row.target}</h2>
        <Badge
          className={cn(
            row.status === 'succeeded'
              ? 'bg-good-soft text-good'
              : row.status === 'failed'
                ? 'bg-bad-soft text-bad'
                : 'bg-info-soft text-info',
          )}
        >
          {row.status}
        </Badge>
      </div>
      <p className="text-[13px] text-hint">
        {row.host_count} hosts · {row.service_count} services ·{' '}
        {relative(row.started_at)}
      </p>
      <p
        className={cn(
          'mt-2 text-[14px] font-medium',
          changed ? 'text-bad' : 'text-good',
        )}
      >
        {row.error
          ? row.error
          : changed
            ? `${row.change_count} changes detected`
            : 'No changes'}
      </p>
    </section>
  )
}