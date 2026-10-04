import * as React from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Network,
  PlusCircle,
  Radio,
  RefreshCw,
  ScanLine,
  ScrollText,
  Server,
  ShieldCheck,
  Users as UsersIcon,
  XCircle,
} from 'lucide-react'
import {
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatDistanceToNow } from 'date-fns'
import { api } from '@/lib/api'
import { cn, formatNumber } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle, Badge, Button } from '@/components/ui'
import { CardSkeleton, ErrorState, Skeleton, StatusDot } from '@/components/feedback'
import { KPICard } from '@/components/kpi-card'

const CHANGE_COLORS: Record<string, string> = {
  new_host: 'rgb(var(--primary))',
  new_port: 'rgb(var(--info))',
  service_change: 'rgb(var(--warning))',
  closed_port: 'rgb(var(--danger))',
  closed_host: 'rgb(148 163 184)',
}

const CHANGE_LABELS: Record<string, string> = {
  new_host: 'New host',
  new_port: 'New port',
  service_change: 'Service changed',
  closed_port: 'Closed port',
  closed_host: 'Closed host',
}

function actionIcon(action: string): React.ReactNode {
  if (action.startsWith('auth')) return <ShieldCheck className="h-4 w-4" />
  if (action.startsWith('user')) return <UsersIcon className="h-4 w-4" />
  if (action.startsWith('settings')) return <Activity className="h-4 w-4" />
  if (action.startsWith('scan')) return <ScanLine className="h-4 w-4" />
  if (action.startsWith('target')) return <Network className="h-4 w-4" />
  if (action.startsWith('schedule')) return <Radio className="h-4 w-4" />
  if (action.startsWith('retention')) return <RefreshCw className="h-4 w-4" />
  return <ScrollText className="h-4 w-4" />
}

function actionTone(action: string, success: boolean): string {
  if (!success) return 'bg-danger-soft text-danger'
  if (action.startsWith('auth.login_failed')) return 'bg-danger-soft text-danger'
  if (action.startsWith('settings')) return 'bg-info-soft text-info'
  if (action.startsWith('scan')) return 'bg-primary-soft text-primary'
  if (action.startsWith('target')) return 'bg-warning-soft text-warning'
  return 'bg-elevated text-muted'
}

export function DashboardPage({ onRefresh }: { onRefresh: () => void }): JSX.Element {
  const queryClient = useQueryClient()
  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['stats'],
    queryFn: ({ signal }) => api.stats(7, signal),
  })

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => api.health(signal),
    refetchInterval: 30_000,
  })

  function refreshAll(): void {
    void queryClient.invalidateQueries()
    onRefresh()
  }

  if (isError) {
    return <ErrorState description="Could not load dashboard data." onRetry={() => void refetch()} />
  }

  const series = data?.series ?? []
  const breakdown = Object.entries(data?.change_breakdown ?? {})
  const dbOk = health?.status === 'ok'

  // Trend is derived from the series so the panel needs no extra endpoint.
  const recent = series.slice(-2)
  const trend = (key: 'scans' | 'changes'): number | null => {
    if (recent.length < 2) return null
    const [previous, current] = recent
    if (!previous || !current) return null
    const base = previous[key]
    if (base === 0) return current[key] > 0 ? 100 : 0
    return ((current[key] - base) / base) * 100
  }

  return (
    <div className="space-y-5">
      {isLoading ? (
        <CardSkeleton />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <KPICard
            label="Targets"
            value={data?.targets ?? 0}
            icon={Network}
            trendLabel="registered"
          />
          <KPICard
            label="Scans (24h)"
            value={data?.scans_24h ?? 0}
            icon={ScanLine}
            trend={trend('scans')}
            trendLabel="vs previous day"
          />
          <KPICard
            label="Changes (24h)"
            value={data?.changes_24h ?? 0}
            icon={AlertTriangle}
            trend={trend('changes')}
            trendLabel="vs previous day"
          />
          <KPICard
            label="Telegram Users"
            value={data?.telegram_users ?? 0}
            icon={UsersIcon}
            trendLabel={`${data?.admins ?? 0} admin(s)`}
          />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={refreshAll} disabled={isFetching}>
          <RefreshCw className={cn('h-4 w-4', isFetching && 'animate-spin')} />
          {isFetching ? 'Refreshing…' : 'Refresh'}
        </Button>
        <Link to="/targets">
          <Button size="sm" variant="outline">
            <PlusCircle className="h-4 w-4" />
            Add target
          </Button>
        </Link>
        <Link to="/audit">
          <Button size="sm" variant="ghost">
            <ScrollText className="h-4 w-4" />
            View audit
          </Button>
        </Link>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Scans and changes — last 7 days</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-64" />
            ) : series.length === 0 ? (
              <p className="py-16 text-center text-sm text-muted">No activity in the last 7 days.</p>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={{ fontSize: 11, fill: 'rgb(var(--muted))' }}
                    tickFormatter={(value: string) => value.slice(5)}
                    stroke="rgb(var(--border))"
                  />
                  <YAxis
                    tick={{ fontSize: 11, fill: 'rgb(var(--muted))' }}
                    allowDecimals={false}
                    stroke="rgb(var(--border))"
                  />
                  <RTooltip
                    contentStyle={{
                      background: 'rgb(var(--surface))',
                      border: '1px solid rgb(var(--border))',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                    labelStyle={{ color: 'rgb(var(--fg))' }}
                  />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line
                    type="monotone"
                    dataKey="scans"
                    name="scans"
                    stroke="rgb(var(--primary))"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="changes"
                    name="changes"
                    stroke="rgb(var(--danger))"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Change types</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-64" />
            ) : breakdown.length === 0 ? (
              <p className="py-16 text-center text-sm text-muted">No change events recorded.</p>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={breakdown.map(([name, value]) => ({ name, value }))}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={52}
                      outerRadius={78}
                      paddingAngle={2}
                      stroke="none"
                    >
                      {breakdown.map(([name]) => (
                        <Cell key={name} fill={CHANGE_COLORS[name] ?? 'rgb(var(--muted))'} />
                      ))}
                    </Pie>
                    <RTooltip
                      contentStyle={{
                        background: 'rgb(var(--surface))',
                        border: '1px solid rgb(var(--border))',
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <ul className="mt-3 space-y-1.5">
                  {breakdown.map(([name, value]) => (
                    <li key={name} className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-2 text-muted">
                        <span
                          className="h-2.5 w-2.5 rounded-full"
                          style={{ background: CHANGE_COLORS[name] ?? 'rgb(var(--muted))' }}
                        />
                        {CHANGE_LABELS[name] ?? name}
                      </span>
                      <span className="tabular-nums text-fg">{formatNumber(value)}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
            <Link to="/audit" className="link text-xs">
              View all
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : (data?.recent_audit ?? []).length === 0 ? (
              <p className="py-10 text-center text-sm text-muted">No activity logged yet.</p>
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
                        {entry.created_at ? formatDistanceToNow(new Date(entry.created_at), { addSuffix: true }) : '—'}
                      </p>
                    </div>
                    {entry.success ? (
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-primary" />
                    ) : (
                      <XCircle className="h-4 w-4 shrink-0 text-danger" />
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>System status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-0 text-sm">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-muted">
                <Server className="h-4 w-4" />
                Database
              </span>
              {health ? <StatusDot ok={dbOk} label={dbOk ? 'reachable' : 'down'} /> : <Skeleton className="h-4 w-16" />}
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
              <span className="text-muted">Alert chat</span>
              <span className="font-mono text-xs text-fg">
                {data?.operator_chat ? data.operator_chat.chat_id : 'not set'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Failed (24h)</span>
              <Badge variant={data && data.scans_24h_failed > 0 ? 'danger' : 'success'}>
                {data?.scans_24h_failed ?? 0}
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}