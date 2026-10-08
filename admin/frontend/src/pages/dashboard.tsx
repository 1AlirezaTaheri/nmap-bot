import * as React from 'react'
import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  CircleDot,
  Database,
  Layers,
  Network,
  PlusCircle,
  RefreshCw,
  ScanLine,
  ScrollText,
  ShieldCheck,
  TrendingUp,
  Users as UsersIcon,
  XCircle,
  Zap,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatDistanceToNow } from 'date-fns'
import { api, type ScheduleStatus, type WorkerStatus } from '@/lib/api'
import { cn, formatNumber } from '@/lib/utils'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui'
import {
  CardSkeleton,
  EmptyState,
  ErrorState,
  Skeleton,
  StatusDot,
} from '@/components/feedback'
import { KPICard } from '@/components/kpi-card'

/** How often the live panels refetch. */
const REFRESH_MS = 15_000

const CHANGE_COLORS: Record<string, string> = {
  new_host: 'rgb(var(--success))',
  new_port: 'rgb(var(--info))',
  service_change: 'rgb(var(--warning))',
  closed_port: 'rgb(var(--danger))',
  closed_host: 'rgb(var(--muted))',
}

const CHANGE_LABELS: Record<string, string> = {
  new_host: 'New host',
  new_port: 'New port',
  service_change: 'Service changed',
  closed_port: 'Closed port',
  closed_host: 'Closed host',
}

/** Shared tooltip styling, so every chart's hover looks the same. */
const CHART_TOOLTIP = {
  contentStyle: {
    background: 'rgb(var(--elevated))',
    border: '1px solid rgb(var(--border))',
    borderRadius: 8,
    fontSize: 12,
    boxShadow: 'var(--shadow-md)',
  },
  labelStyle: { color: 'rgb(var(--fg))' },
  cursor: { stroke: 'rgb(var(--border))' },
} as const

const AXIS_TICK = { fontSize: 11, fill: 'rgb(var(--muted))' } as const

function actionIcon(action: string): React.ReactNode {
  if (action.startsWith('auth')) return <ShieldCheck className="h-4 w-4" aria-hidden />
  if (action.startsWith('telegram_user') || action.startsWith('user'))
    return <UsersIcon className="h-4 w-4" aria-hidden />
  if (action.startsWith('settings'))
    return <Activity className="h-4 w-4" aria-hidden />
  if (action.startsWith('scan')) return <ScanLine className="h-4 w-4" aria-hidden />
  if (action.startsWith('target'))
    return <Network className="h-4 w-4" aria-hidden />
  if (action.startsWith('schedule'))
    return <CalendarClock className="h-4 w-4" aria-hidden />
  if (action.startsWith('retention')) return <RefreshCw className="h-4 w-4" aria-hidden />
  return <ScrollText className="h-4 w-4" aria-hidden />
}

function actionTone(action: string, success: boolean): string {
  if (!success) return 'bg-danger-soft text-danger'
  if (action.startsWith('auth.login_failed')) return 'bg-danger-soft text-danger'
  if (action.startsWith('settings')) return 'bg-info-soft text-info'
  if (action.startsWith('scan')) return 'bg-success-soft text-success'
  if (action.startsWith('target')) return 'bg-warning-soft text-warning'
  return 'bg-elevated text-muted'
}

/** "updated 5s ago", recomputed on its own timer so it ticks between refetches. */
/**
 * Re-render on an interval so relative timestamps stay honest.
 *
 * Returns nothing: `formatDistanceToNow` reads the clock itself, so all
 * this needs to do is make the component re-render. The earlier version
 * returned the timestamp and every caller ignored it, which
 * noUnusedLocals correctly flagged.
 */
function useTick(intervalMs = 5_000): void {
  const [, setTick] = React.useState(0)
  React.useEffect(() => {
    const id = window.setInterval(() => setTick((n) => n + 1), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
}

function Freshness({ at }: { at: number | null }): JSX.Element | null {
  useTick()
  if (at === null) return null
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-success" aria-hidden />
      updated {formatDistanceToNow(new Date(at), { addSuffix: false })} ago
    </span>
  )
}

export function DashboardPage({ onRefresh }: { onRefresh: () => void }): JSX.Element {
  const queryClient = useQueryClient()

  const stats = useQuery({
    queryKey: ['stats', 7],
    queryFn: ({ signal }) => api.stats(7, signal),
    refetchInterval: REFRESH_MS,
  })

  const topTargets = useQuery({
    queryKey: ['stats', 'top-targets', 7],
    queryFn: ({ signal }) => api.topTargets(7, signal),
    refetchInterval: REFRESH_MS,
  })

  const worker = useQuery({
    queryKey: ['stats', 'worker'],
    queryFn: ({ signal }) => api.workerStatus(signal),
    refetchInterval: REFRESH_MS,
  })

  const schedule = useQuery({
    queryKey: ['stats', 'schedule'],
    queryFn: ({ signal }) => api.scheduleStatus(signal),
    refetchInterval: REFRESH_MS,
  })

  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => api.health(signal),
    refetchInterval: 30_000,
  })

  const data = stats.data
  const series = data?.series ?? []
  const breakdown = useMemo(
    () =>
      Object.entries(data?.change_breakdown ?? {})
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value),
    [data?.change_breakdown],
  )

  const dbOk = health.data?.status === 'ok'

  // Trend from the last two days of the series, so no extra endpoint is needed.
  const recent = series.slice(-2)
  const trend = (key: 'scans' | 'changes'): number | null => {
    if (recent.length < 2) return null
    const [previous, current] = recent
    if (!previous || !current) return null
    const base = previous[key]
    if (base === 0) return current[key] > 0 ? 100 : 0
    return ((current[key] - base) / base) * 100
  }

  // "Today" is the last bucket, which daily_series() guarantees is the current
  // date or earlier. Reading it from the series rather than querying again
  // keeps every number on the page consistent with the chart below it.
  const today = series[series.length - 1]
  const isFetching = stats.isFetching || worker.isFetching

  function refreshAll(): void {
    void queryClient.invalidateQueries()
    onRefresh()
  }

  if (stats.isError) {
    return (
      <ErrorState
        description="Could not load dashboard data."
        onRetry={() => void stats.refetch()}
      />
    )
  }

  return (
    <div className="space-y-5">
      {/* --- toolbar --------------------------------------------------- */}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={refreshAll} disabled={isFetching}>
          <RefreshCw className={cn('h-4 w-4', isFetching && 'animate-spin')} aria-hidden />
          {isFetching ? 'Refreshingâ€¦' : 'Refresh'}
        </Button>
        <Link to="/targets">
          <Button size="sm" variant="outline">
            <PlusCircle className="h-4 w-4" aria-hidden />
            Add target
          </Button>
        </Link>
        <Link to="/audit">
          <Button size="sm" variant="ghost">
            <ScrollText className="h-4 w-4" aria-hidden />
            View audit
          </Button>
        </Link>

        <span className="ml-auto flex items-center gap-3">
          <Freshness at={stats.dataUpdatedAt || null} />
          <Badge variant="muted" title="Live panels refresh every 15 seconds">
            <CircleDot className="h-3 w-3" aria-hidden />
            15s
          </Badge>
        </span>
      </div>

      {/* --- stat tiles ------------------------------------------------- */}
      {stats.isLoading ? (
        <CardSkeleton count={6} />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <KPICard
            label="Targets"
            value={data?.targets ?? 0}
            icon={Network}
            trendLabel="registered"
            hint="Every target in the registry, enabled or not."
          />
          <KPICard
            label="Scans today"
            value={today?.scans ?? 0}
            icon={ScanLine}
            trend={trend('scans')}
            trendLabel="vs yesterday"
            hint="Scans that started today, from the same series the chart plots."
          />
          <KPICard
            label="Changes today"
            value={today?.changes ?? 0}
            icon={AlertTriangle}
            trend={trend('changes')}
            trendLabel="vs yesterday"
            hint="Difference events recorded today across all targets and profiles."
            tone={today && today.changes > 0 ? 'warning' : 'neutral'}
          />
          <WorkerTile worker={worker.data} loading={worker.isLoading} />
          <KPICard
            label="Failed (24h)"
            value={data?.scans_24h_failed ?? 0}
            icon={XCircle}
            trendLabel="scans"
            hint="Scans that ended in a failed state in the last 24 hours."
            tone={(data?.scans_24h_failed ?? 0) > 0 ? 'danger' : 'neutral'}
          />
          <ScheduleTile schedule={schedule.data} loading={schedule.isLoading} />
        </div>
      )}

      {/* --- charts ----------------------------------------------------- */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Scan activity â€” last 7 days</CardTitle>
            <span className="text-xs text-muted">scans and change events per day</span>
          </CardHeader>
          <CardContent>
            {stats.isLoading ? (
              <Skeleton className="h-64" />
            ) : series.length === 0 ? (
              <EmptyState
                icon={ScanLine}
                title="No activity yet"
                description="Run a scan from Telegram with /scan and it will appear here."
              />
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="fillScans" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="rgb(var(--primary))" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="rgb(var(--primary))" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="fillFailed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="rgb(var(--danger))" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="rgb(var(--danger))" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={AXIS_TICK}
                    tickFormatter={(value: string) => value.slice(5)}
                    stroke="rgb(var(--border))"
                  />
                  <YAxis tick={AXIS_TICK} allowDecimals={false} stroke="rgb(var(--border))" />
                  <RTooltip {...CHART_TOOLTIP} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Area
                    type="monotone"
                    dataKey="scans"
                    name="scans"
                    stroke="rgb(var(--primary))"
                    strokeWidth={2}
                    fill="url(#fillScans)"
                  />
                  <Area
                    type="monotone"
                    dataKey="failed"
                    name="failed"
                    stroke="rgb(var(--danger))"
                    strokeWidth={2}
                    fill="url(#fillFailed)"
                  />
                  <Line
                    type="monotone"
                    dataKey="changes"
                    name="changes"
                    stroke="rgb(var(--warning))"
                    strokeWidth={2}
                    dot={{ r: 2 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Change types â€” last 7 days</CardTitle>
          </CardHeader>
          <CardContent>
            {stats.isLoading ? (
              <Skeleton className="h-64" />
            ) : breakdown.length === 0 ? (
              <EmptyState
                icon={Layers}
                title="No change events"
                description="Changes appear once a second scan finds a difference."
              />
            ) : (
              <>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={breakdown} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                    <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="name"
                      tick={AXIS_TICK}
                      tickFormatter={(value: string) => CHANGE_LABELS[value] ?? value}
                      stroke="rgb(var(--border))"
                    />
                    <YAxis tick={AXIS_TICK} allowDecimals={false} stroke="rgb(var(--border))" />
                    <RTooltip
                      {...CHART_TOOLTIP}
                      labelFormatter={(value: string) => CHANGE_LABELS[value] ?? value}
                    />
                    <Bar dataKey="value" name="events" radius={[4, 4, 0, 0]}>
                      {breakdown.map((entry) => (
                        <Cell key={entry.name} fill={CHANGE_COLORS[entry.name] ?? 'rgb(var(--muted))'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <ul className="mt-3 space-y-1.5">
                  {breakdown.map((entry) => (
                    <li key={entry.name} className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-2 text-muted">
                        <span
                          className="h-2.5 w-2.5 rounded-full"
                          style={{ background: CHANGE_COLORS[entry.name] ?? 'rgb(var(--muted))' }}
                          aria-hidden
                        />
                        {CHANGE_LABELS[entry.name] ?? entry.name}
                      </span>
                      <span className="tabular-nums text-fg">{formatNumber(entry.value)}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* --- lower panels ----------------------------------------------- */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
            <Link to="/audit" className="link text-xs">
              View all
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {stats.isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : (data?.recent_audit ?? []).length === 0 ? (
              <EmptyState
                icon={ScrollText}
                title="Nothing logged yet"
                description="Sign-ins, target changes and setting updates are recorded here."
              />
            ) : (
              <ul className="divide-y divide-border/60">
                {data?.recent_audit.map((entry) => (
                  <li key={entry.id} className="flex items-center gap-3 py-2.5">
                    <span
                      className={cn(
                        'flex h-8 w-8 shrink-0 items-center justify-center rounded-md',
                        actionTone(entry.action, entry.success),
                      )}
                    >
                      {actionIcon(entry.action)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-fg">
                        <span className="font-medium">
                          {entry.actor_username ?? entry.actor_type}
                        </span>{' '}
                        <span className="font-mono text-xs text-muted">{entry.action}</span>
                      </p>
                      <p className="text-xs text-muted">
                        {entry.created_at
                          ? formatDistanceToNow(new Date(entry.created_at), { addSuffix: true })
                          : 'â€”'}
                      </p>
                    </div>
                    {entry.success ? (
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden />
                    ) : (
                      <XCircle className="h-4 w-4 shrink-0 text-danger" aria-hidden />
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <TopTargetsPanel
            loading={topTargets.isLoading}
            error={topTargets.isError}
            onRetry={() => void topTargets.refetch()}
            targets={topTargets.data?.targets ?? []}
            days={topTargets.data?.days ?? 7}
          />

          <Card>
            <CardHeader>
              <CardTitle>System status</CardTitle>
              <Freshness at={health.dataUpdatedAt || null} />
            </CardHeader>
            <CardContent className="space-y-3 pt-0 text-sm">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-muted">
                  <Database className="h-4 w-4" aria-hidden />
                  Database
                </span>
                {health.data ? (
                  <StatusDot ok={dbOk} label={dbOk ? 'reachable' : 'down'} />
                ) : (
                  <Skeleton className="h-4 w-16" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">Hosts recorded</span>
                <span className="tabular-nums text-fg">{formatNumber(data?.hosts ?? 0)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">Services recorded</span>
                <span className="tabular-nums text-fg">{formatNumber(data?.services ?? 0)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">Last scan</span>
                <span className="text-xs text-fg">
                  {data?.last_scan_at
                    ? formatDistanceToNow(new Date(data.last_scan_at), { addSuffix: true })
                    : 'never'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">Telegram users</span>
                <span className="tabular-nums text-fg">
                  {formatNumber(data?.telegram_users ?? 0)}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Tiles that need a query of their own                                        */
/* -------------------------------------------------------------------------- */

function WorkerTile({
  worker,
  loading,
}: {
  worker: WorkerStatus | undefined
  loading: boolean
}): JSX.Element {
  if (loading) {
    return (
      <div className="rounded-lg border border-border bg-surface p-4">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="mt-3 h-8 w-16" />
      </div>
    )
  }

  // Worker construction is wrapped in a try/except in bootstrap, so this
  // branch is reachable: the admin normally DOES run a worker for the Mini
  // App, and reports real counters. Say plainly that the worker is unavailable
  // rather than showing zeros, which would read as "idle".
  if (!worker?.available) {
    return (
      <div className="rounded-lg border border-border bg-surface p-4">
        <p className="truncate text-xs font-medium uppercase tracking-wide text-muted">
          Scan worker
        </p>
        <p className="mt-2 text-sm text-danger">Unavailable</p>
        <p className="mt-2 text-xs text-muted">
          This process could not start a worker. Check the admin log.
        </p>
      </div>
    )
  }

  return (
    <KPICard
      label="Active scans"
      value={worker.active ?? 0}
      icon={Zap}
      tone={worker.active ? 'info' : 'neutral'}
      hint="Jobs currently executing on the admin process's worker. The bot process runs a separate one, so this is the panel's view and not a deployment-wide total."
      footer={
        <>
          <span className="inline-flex items-center gap-1">
            {worker.running ? (
              <StatusDot ok label="running" />
            ) : (
              <StatusDot ok={false} label="stopped" />
            )}
          </span>
          {' Â· '}
          <span className="tabular-nums">{worker.queue_depth ?? 0}</span> queued
          {worker.max_concurrency !== null ? ` Â· ${worker.max_concurrency} slot(s)` : ''}
        </>
      }
    />
  )
}

function ScheduleTile({
  schedule,
  loading,
}: {
  schedule: ScheduleStatus | undefined
  loading: boolean
}): JSX.Element {
  if (loading) {
    return (
      <div className="rounded-lg border border-border bg-surface p-4">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="mt-3 h-8 w-16" />
      </div>
    )
  }

  if (!schedule) {
    return (
      <div className="rounded-lg border border-border bg-surface p-4">
        <p className="truncate text-xs font-medium uppercase tracking-wide text-muted">
          Schedule
        </p>
        <p className="mt-2 text-sm text-muted">Unknown</p>
      </div>
    )
  }

  return (
    <KPICard
      label="Schedule"
      value={schedule.enabled ? 'On' : 'Off'}
      icon={CalendarClock}
      tone={schedule.enabled ? 'primary' : 'neutral'}
      hint="The scheduler switch. The next-run time is not tracked anywhere, so it is not shown rather than estimated."
      footer={
        schedule.enabled ? (
          schedule.interval_hours !== null ? (
            <>every {schedule.interval_hours}h</>
          ) : (
            'interval unknown'
          )
        ) : (
          'disabled in settings'
        )
      }
    />
  )
}

function TopTargetsPanel({
  targets,
  days,
  loading,
  error,
  onRetry,
}: {
  targets: Array<{
    id: number
    name: string
    value: string
    changes: number
    last_change_at: string | null
  }>
  days: number
  loading: boolean
  error: boolean
  onRetry: () => void
}): JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Most-changed targets</CardTitle>
        <span className="text-xs text-muted">last {days}d</span>
      </CardHeader>
      <CardContent className="pt-0">
        {loading ? (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-9" />
            ))}
          </div>
        ) : error ? (
          <p className="py-6 text-center text-sm text-muted">
            Could not load.{' '}
            <button type="button" onClick={onRetry} className="link">
              Retry
            </button>
          </p>
        ) : targets.length === 0 ? (
          <EmptyState
            icon={TrendingUp}
            title="No changes"
            description="Nothing changed in this window, which is the healthy case."
          />
        ) : (
          <ul className="divide-y divide-border/60">
            {targets.map((target, index) => (
              <li key={target.id}>
                <Link
                  to={`/targets?q=${encodeURIComponent(target.name)}`}
                  className="flex items-center gap-3 py-2.5 transition-colors hover:text-primary"
                >
                  <span className="w-4 shrink-0 text-xs tabular-nums text-faint">
                    {index + 1}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-fg">
                      {target.name}
                    </span>
                    <span className="block truncate font-mono text-[11px] text-muted">
                      {target.value}
                    </span>
                  </span>
                  <Badge variant={target.changes > 10 ? 'warning' : 'muted'}>
                    {formatNumber(target.changes)}
                  </Badge>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}