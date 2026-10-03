import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { format, isToday, isYesterday, parseISO } from 'date-fns'
import { formatDistanceToNow } from 'date-fns'
import {
  Activity,
  Download,
  Network,
  Radio,
  RefreshCw,
  ScanLine,
  ScrollText,
  Search,
  ShieldCheck,
  Users as UsersIcon,
} from 'lucide-react'
import { api, type AuditEntry, type AuditFilters } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Badge, Button, Card, Input } from '@/components/ui'
import { EmptyState, Skeleton, StatusDot } from '@/components/feedback'

const ACTIONS = [
  'auth.login',
  'auth.login_failed',
  'auth.logout',
  'user.add',
  'user.update',
  'user.delete',
  'settings.update',
  'target.add',
  'target.delete',
  'target.purge',
  'scan.requested',
  'scan.completed',
  'scan.failed',
  'schedule.add',
  'schedule.remove',
  'schedule.pause',
  'schedule.resume',
  'retention.run',
  'export.run',
  'report.run',
]

function iconFor(action: string): React.ReactNode {
  if (action.startsWith('auth')) return <ShieldCheck className="h-4 w-4" />
  if (action.startsWith('user')) return <UsersIcon className="h-4 w-4" />
  if (action.startsWith('scan')) return <ScanLine className="h-4 w-4" />
  if (action.startsWith('target')) return <Network className="h-4 w-4" />
  if (action.startsWith('schedule')) return <Radio className="h-4 w-4" />
  if (action.startsWith('settings')) return <Activity className="h-4 w-4" />
  return <ScrollText className="h-4 w-4" />
}

function toneFor(action: string, success: boolean): string {
  if (!success) return 'bg-danger-soft text-danger'
  if (action.includes('login_failed')) return 'bg-danger-soft text-danger'
  if (action.startsWith('settings') || action.startsWith('retention')) return 'bg-info-soft text-info'
  if (action.startsWith('scan')) return 'bg-primary-soft text-primary'
  if (action.startsWith('target')) return 'bg-warning-soft text-warning'
  if (action.startsWith('user')) return 'bg-elevated text-fg'
  return 'bg-elevated text-muted'
}

function dayLabel(iso: string): string {
  try {
    const date = parseISO(iso)
    if (isToday(date)) return 'Today'
    if (isYesterday(date)) return 'Yesterday'
    return format(date, 'EEEE, d MMMM yyyy')
  } catch {
    return iso.slice(0, 10)
  }
}

export function AuditPage(): JSX.Element {
  const [search, setSearch] = React.useState('')
  const [action, setAction] = React.useState('')
  const [success, setSuccess] = React.useState('')
  const [actorId, setActorId] = React.useState('')
  const [live, setLive] = React.useState(false)

  const filters: AuditFilters = React.useMemo(
    () => ({
      page: 1,
      page_size: 200,
      ...(action ? { action } : {}),
      ...(success ? { success: success === 'true' } : {}),
      ...(actorId ? { actor_id: Number(actorId) } : {}),
    }),
    [action, success, actorId],
  )

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['audit', filters],
    queryFn: ({ signal }) => api.audit(filters, signal),
    // "Live tail": cheap poll, only when explicitly enabled.
    refetchInterval: live ? 5_000 : false,
    refetchIntervalInBackground: false,
  })

  const entries = React.useMemo(() => {
    const all = data?.entries ?? []
    const needle = search.trim().toLowerCase()
    if (!needle) return all
    return all.filter((entry) =>
      `${entry.action} ${entry.actor_username ?? ''} ${entry.actor_type} ${entry.target_type ?? ''} ${entry.target_id ?? ''}`
        .toLowerCase()
        .includes(needle),
    )
  }, [data, search])

  const grouped = React.useMemo(() => {
    const map = new Map<string, AuditEntry[]>()
    for (const entry of entries) {
      const key = entry.created_at ? dayLabel(entry.created_at) : 'Unknown'
      const bucket = map.get(key)
      if (bucket) bucket.push(entry)
      else map.set(key, [entry])
    }
    return [...map.entries()]
  }, [entries])

  const csvUrl = api.auditCsvUrl({
    ...(action ? { action } : {}),
    ...(success ? { success: success === 'true' } : {}),
    ...(actorId ? { actor_id: Number(actorId) } : {}),
  })

  return (
    <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
      <Card className="h-fit p-3">
        <p className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-muted">Filters</p>

        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs text-muted" htmlFor="f-action">
              Action
            </label>
            <select
              id="f-action"
              className="input h-8 text-xs"
              value={action}
              onChange={(event) => setAction(event.target.value)}
            >
              <option value="">all actions</option>
              {ACTIONS.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs text-muted" htmlFor="f-success">
              Result
            </label>
            <select
              id="f-success"
              className="input h-8 text-xs"
              value={success}
              onChange={(event) => setSuccess(event.target.value)}
            >
              <option value="">all results</option>
              <option value="true">success only</option>
              <option value="false">failures only</option>
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs text-muted" htmlFor="f-actor">
              Actor ID
            </label>
            <input
              id="f-actor"
              className="input h-8 text-xs"
              inputMode="numeric"
              placeholder="7575983824"
              value={actorId}
              onChange={(event) => setActorId(event.target.value.replace(/\D/g, ''))}
            />
          </div>

          <div className="space-y-2 border-t border-border pt-3">
            <label className="flex cursor-pointer items-center justify-between gap-2 text-xs text-fg">
              <span className="flex items-center gap-1.5">
                <Radio className={cn('h-3.5 w-3.5', live ? 'text-primary' : 'text-muted')} />
                Live tail
              </span>
              <input
                type="checkbox"
                checked={live}
                onChange={(event) => setLive(event.target.checked)}
                className="h-3.5 w-3.5 accent-[rgb(var(--primary))]"
              />
            </label>
            {live ? <StatusDot ok label="refreshing every 5s" /> : null}

            <a href={csvUrl} download className="block">
              <Button variant="outline" size="sm" className="w-full">
                <Download className="h-3.5 w-3.5" />
                Export CSV
              </Button>
            </a>
          </div>

          <p className="border-t border-border pt-3 text-xs text-muted">
            {data?.total ?? 0} entr{data?.total === 1 ? 'y' : 'ies'} matched
          </p>
        </div>
      </Card>

      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <Input
              className="pl-9"
              placeholder="Search action, actor or target…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <Button
            variant="outline"
            size="icon"
            aria-label="Refresh"
            onClick={() => void refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn('h-4 w-4', isFetching && 'animate-spin')} />
          </Button>
        </div>

        {isLoading ? (
          <Card className="space-y-3 p-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </Card>
        ) : entries.length === 0 ? (
          <Card>
            <EmptyState
              title="No audit entries match"
              description="Adjust the filters or clear the search."
            />
          </Card>
        ) : (
          <div className="space-y-5">
            {grouped.map(([day, items]) => (
              <div key={day}>
                <div className="mb-2 flex items-center gap-3">
                  <span className="text-xs font-semibold text-fg">{day}</span>
                  <span className="text-xs text-muted">({items.length})</span>
                  <span className="h-px flex-1 bg-border" />
                </div>

                <ol className="relative space-y-1 border-l border-border pl-5">
                  {items.map((entry) => (
                    <li key={entry.id} className="relative py-1.5">
                      <span
                        className={cn(
                          'absolute -left-[26px] top-3 flex h-5 w-5 items-center justify-center rounded-full ring-4 ring-bg',
                          toneFor(entry.action, entry.success),
                        )}
                      >
                        {iconFor(entry.action)}
                      </span>

                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="text-sm font-medium text-fg">
                          {entry.actor_username ?? entry.actor_type}
                        </span>
                        <span className="font-mono text-xs text-muted">{entry.action}</span>
                        {entry.target_type ? (
                          <span className="font-mono text-xs text-faint">
                            {entry.target_type}
                            {entry.target_id ? `/${entry.target_id}` : ''}
                          </span>
                        ) : null}
                        <Badge variant={entry.success ? 'success' : 'danger'}>
                          {entry.success ? 'ok' : 'failed'}
                        </Badge>
                        <span
                          className="ml-auto text-xs text-muted"
                          title={entry.created_at ?? ''}
                        >
                          {entry.created_at
                            ? formatDistanceToNow(new Date(entry.created_at), { addSuffix: true })
                            : '—'}
                        </span>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}