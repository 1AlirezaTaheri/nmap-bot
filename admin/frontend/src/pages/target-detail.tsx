import * as React from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  CalendarClock,
  ChevronDown,
  Copy,
  Network,
  ScanLine,
  Trash2,
} from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { format, formatDistanceToNow, parseISO } from 'date-fns'
import { toast } from 'sonner'
import { api, ApiError, type PortCount, type ScanHost } from '@/lib/api'
import { cn, formatNumber } from '@/lib/utils'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui'
import {
  EmptyState,
  ErrorState,
  Skeleton,
  TableSkeleton,
} from '@/components/feedback'
import { DataTable, Pagination, type Column, type SortSpec } from '@/components/data-table'
import { ScanButton } from '@/components/scan-button'
import { Tabs, TabsContent } from '@/components/ui'

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

function when(value: string | null | undefined): string {
  if (!value) return 'â€”'
  try {
    return formatDistanceToNow(parseISO(value), { addSuffix: true })
  } catch {
    return 'â€”'
  }
}

function whenExact(value: string | null | undefined): string {
  if (!value) return 'â€”'
  try {
    return format(parseISO(value), 'yyyy-MM-dd HH:mm')
  } catch {
    return 'â€”'
  }
}

function statusVariant(status: string): 'success' | 'danger' | 'warning' | 'muted' {
  switch (status) {
    case 'completed':
    case 'done':
      return 'success'
    case 'failed':
    case 'error':
      return 'danger'
    case 'running':
    case 'queued':
      return 'warning'
    default:
      return 'muted'
  }
}

export function TargetDetailPage(): JSX.Element {
  const { id } = useParams<{ id: string }>()
  const targetId = Number(id)
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [days, setDays] = React.useState(30)
  const [scanPage, setScanPage] = React.useState(1)
  const [scanPageSize, setScanPageSize] = React.useState(10)
  const [profileFilter, setProfileFilter] = React.useState<string>('all')
  const [statusFilter, setStatusFilter] = React.useState<string>('all')
  const [scanSort, setScanSort] = React.useState<readonly SortSpec[]>([
    { key: 'started_at', direction: 'desc' },
  ])
  const [deleteOpen, setDeleteOpen] = React.useState(false)
  const [expanded, setExpanded] = React.useState<ReadonlySet<number>>(new Set())

  const invalidId = !Number.isFinite(targetId) || targetId <= 0

  const detail = useQuery({
    queryKey: ['target', targetId],
    queryFn: ({ signal }) => api.target(targetId, signal),
    enabled: !invalidId,
  })

  const timeline = useQuery({
    queryKey: ['target', targetId, 'timeline', days],
    queryFn: ({ signal }) => api.targetTimeline(targetId, days, signal),
    enabled: !invalidId,
    refetchInterval: 30_000,
  })

  const scans = useQuery({
    queryKey: ['target', targetId, 'scans'],
    queryFn: ({ signal }) => api.targetScans(targetId, signal, 200),
    enabled: !invalidId,
  })

  const changes = useQuery({
    queryKey: ['target', targetId, 'changes'],
    queryFn: ({ signal }) => api.targetChanges(targetId, signal, 200),
    enabled: !invalidId,
  })

  // The newest completed scan is the one worth showing hosts for.
  const latestScan = React.useMemo(() => {
    const list = scans.data?.scans ?? []
    return (
      list.find((s) => s.status === 'completed') ?? list[0] ?? null
    )
  }, [scans.data])

  const latestScanId = latestScan?.id ?? null
  const hosts = useQuery({
    queryKey: ['target', targetId, 'scan', latestScanId, 'hosts'],
    queryFn: ({ signal }) =>
      api.scanHosts(targetId, latestScanId as number, signal),
    // enabled is not a type guard, so the id is asserted inside queryFn
    // rather than silently passed as NaN.
    enabled: !invalidId && latestScanId !== null,
  })

  const purge = useMutation({
    mutationFn: () => api.deleteTarget(targetId, true),
    onSuccess: () => {
      void queryClient.invalidateQueries()
      toast.success('Target deleted')
      navigate('/targets', { replace: true })
    },
    onError: (error) => {
      toast.error(
        error instanceof ApiError ? error.message : 'Could not delete the target.',
      )
    },
  })

  function copyValue(): void {
    const value = detail.data?.value
    if (!value) return
    void navigator.clipboard
      ?.writeText(value)
      .then(() => toast.success(`Copied ${value}`))
      .catch(() => toast.error('Clipboard unavailable'))
  }

  function toggleHost(hostId: number): void {
    setExpanded((previous) => {
      const next = new Set(previous)
      if (next.has(hostId)) next.delete(hostId)
      else next.add(hostId)
      return next
    })
  }

  if (invalidId) {
    return (
      <ErrorState
        title="No such target"
        description="That link has no target id in it."
      />
    )
  }

  if (detail.isError) {
    return (
      <ErrorState
        title="Target not found"
        description="It may have been deleted, or the id is wrong."
        onRetry={() => void detail.refetch()}
      />
    )
  }

  if (detail.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton variant="card" className="h-24" />
        <Skeleton className="h-64" />
      </div>
    )
  }

  const target = detail.data
  const series = timeline.data?.series ?? []

  const allScans = scans.data?.scans ?? []
  const filteredScans = allScans.filter((scan) => {
    if (profileFilter !== 'all' && scan.profile !== profileFilter) return false
    if (statusFilter !== 'all' && scan.status !== statusFilter) return false
    return true
  })

  const profiles = [...new Set(allScans.map((s) => s.profile))].sort()
  const statuses = [...new Set(allScans.map((s) => s.status))].sort()

  const scanColumns: Column<(typeof allScans)[number]>[] = [
    {
      key: 'started_at',
      header: 'Started',
      cell: (row) => (
        <span title={whenExact(row.started_at)}>{when(row.started_at)}</span>
      ),
      sortValue: (row) => row.started_at ?? '',
      sortable: true,
      keepVisible: true,
      resizable: true,
    },
    {
      key: 'profile',
      header: 'Profile',
      cell: (row) => <span className="font-mono text-xs">{row.profile}</span>,
      sortValue: (row) => row.profile,
      sortable: true,
      resizable: true,
    },
    {
      key: 'status',
      header: 'Status',
      cell: (row) => <Badge variant={statusVariant(row.status)}>{row.status}</Badge>,
      sortValue: (row) => row.status,
      sortable: true,
      resizable: true,
    },
    {
      key: 'duration_ms',
      header: 'Duration',
      cell: (row) =>
        row.duration_ms === null ? (
          <span className="text-faint">â€”</span>
        ) : (
          <span className="tabular-nums">
            {row.duration_ms < 1000
              ? `${row.duration_ms} ms`
              : `${(row.duration_ms / 1000).toFixed(1)} s`}
          </span>
        ),
      sortValue: (row) => row.duration_ms ?? -1,
      sortable: true,
      className: 'text-right',
    },
    {
      key: 'host_count',
      header: 'Hosts',
      cell: (row) => <span className="tabular-nums">{formatNumber(row.host_count)}</span>,
      sortValue: (row) => row.host_count,
      sortable: true,
      className: 'text-right',
    },
    {
      key: 'service_count',
      header: 'Services',
      cell: (row) => <span className="tabular-nums">{formatNumber(row.service_count)}</span>,
      sortValue: (row) => row.service_count,
      sortable: true,
      className: 'text-right',
    },
    {
      key: 'changes',
      header: 'Changes',
      cell: (row) => {
        const count = (changes.data?.changes ?? []).filter(
          (c) => c.scan_id === row.id,
        ).length
        return count > 0 ? (
          <Badge variant="warning">{formatNumber(count)}</Badge>
        ) : (
          <span className="text-faint">0</span>
        )
      },
      sortable: false,
    },
  ]

  const sortedScans = React.useMemo(() => {
    const [spec] = scanSort
    if (!spec) return filteredScans
    const dir = spec.direction === 'asc' ? 1 : -1
    return [...filteredScans].sort((a, b) => {
      const key = spec.key as keyof (typeof allScans)[number]
      const av = a[key]
      const bv = b[key]
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir
      return String(av ?? '').localeCompare(String(bv ?? '')) * dir
    })
  }, [filteredScans, scanSort, allScans])

  const pagedScans = sortedScans.slice(
    (scanPage - 1) * scanPageSize,
    scanPage * scanPageSize,
  )

  React.useEffect(() => {
    // A filter that shrinks the list can strand the user on a page that no
    // longer exists, showing an empty table.
    const maxPage = Math.max(1, Math.ceil(sortedScans.length / scanPageSize))
    if (scanPage > maxPage) setScanPage(maxPage)
  }, [sortedScans.length, scanPageSize, scanPage])

  return (
    <div className="space-y-5">
      {/* --- header -------------------------------------------------- */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Link
            to="/targets"
            className="mb-1 inline-flex items-center gap-1 text-xs text-muted transition-colors hover:text-fg"
          >
            <ArrowLeft className="h-3 w-3" aria-hidden />
            All targets
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold text-fg">{target?.name}</h1>
            <Badge variant={target?.enabled ? 'success' : 'muted'}>
              {target?.enabled ? 'enabled' : 'disabled'}
            </Badge>
            {target?.group ? <Badge>{target.group}</Badge> : null}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <code className="rounded bg-elevated px-1.5 py-0.5 font-mono text-xs text-fg">
              {target?.value}
            </code>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6"
                  onClick={copyValue}
                  aria-label="Copy target value"
                >
                  <Copy className="h-3 w-3" aria-hidden />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Copy</TooltipContent>
            </Tooltip>
            <span className="text-xs text-muted">
              {formatNumber(target?.scan_count ?? 0)} scan(s) Â· added{' '}
              {whenExact(target?.created_at)}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Primary action. Placed with the header rather than near the
              scans table because it applies to the target, not to one row. */}
          {target ? (
            <ScanButton
              targetId={target.id}
              targetName={target.name}
              variant="default"
              onQueued={() => {
                // A queued scan has not produced a row yet, so the scans list
                // will not change on its own. Refetch once the job lands.
                window.setTimeout(() => {
                  void queryClient.invalidateQueries({
                    queryKey: ['target', targetId],
                  })
                }, 4_000)
              }}
            />
          ) : null}
          <Button variant="outline" size="sm" onClick={() => void queryClient.invalidateQueries()}>
            Refresh
          </Button>
          <Button variant="danger" size="sm" onClick={() => setDeleteOpen(true)}>
            <Trash2 className="h-4 w-4" aria-hidden />
            Delete
          </Button>
        </div>
      </div>

      {/* --- schedule ------------------------------------------------ */}
      {target?.schedule ? (
        <Card className="p-3">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <span className="flex items-center gap-2">
              <CalendarClock className="h-4 w-4 text-muted" aria-hidden />
              <span className="text-muted">Scheduled</span>
              <Badge variant={target.schedule.enabled ? 'info' : 'muted'}>
                {target.schedule.enabled ? 'on' : 'off'}
              </Badge>
            </span>
            <span className="text-xs text-muted">
              profile <span className="font-mono text-fg">{target.schedule.profile}</span>{' '}
              every {target.schedule.interval_hours}h
            </span>
            <span className="text-xs text-muted">
              last run {when(target.schedule.last_run_at)}
            </span>
            {/* A schedule row does persist next_run_at, so unlike the global
                scheduler this can be shown for real rather than estimated. */}
            <span className="text-xs text-muted">
              next run {whenExact(target.schedule.next_run_at)}
            </span>
          </div>
        </Card>
      ) : (
        <Card className="flex items-center gap-2 p-3 text-sm text-muted">
          <Ban className="h-4 w-4" aria-hidden />
          No schedule for this target. Scans run only on demand.
        </Card>
      )}

      {/* --- timeline chart ------------------------------------------ */}
      <Card>
        <CardHeader>
          <CardTitle>Activity â€” last {days} days</CardTitle>
          <div className="flex items-center gap-1" role="group" aria-label="Time window">
            {[7, 30, 90].map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setDays(option)}
                aria-pressed={days === option}
                className={cn(
                  'rounded-md px-2 py-1 text-xs transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
                  days === option
                    ? 'bg-primary text-primary-fg'
                    : 'text-muted hover:bg-elevated hover:text-fg',
                )}
              >
                {option}d
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          {timeline.isLoading ? (
            <Skeleton className="h-56" />
          ) : series.length === 0 ? (
            <EmptyState
              icon={ScanLine}
              title="No activity"
              description="This target has not been scanned in the selected window."
            />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={series} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={AXIS_TICK}
                  tickFormatter={(value: string) => value.slice(5)}
                  stroke="rgb(var(--border))"
                />
                <YAxis tick={AXIS_TICK} allowDecimals={false} stroke="rgb(var(--border))" />
                <RTooltip {...CHART_TOOLTIP} />
                <Line
                  type="monotone"
                  dataKey="scans"
                  name="scans"
                  stroke="rgb(var(--primary))"
                  strokeWidth={2}
                  dot={{ r: 2 }}
                />
                <Line
                  type="monotone"
                  dataKey="changes"
                  name="changes"
                  stroke="rgb(var(--warning))"
                  strokeWidth={2}
                  dot={{ r: 2 }}
                />
                <Line
                  type="monotone"
                  dataKey="failed"
                  name="failed"
                  stroke="rgb(var(--danger))"
                  strokeWidth={2}
                  dot={{ r: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* --- scans / hosts / changes --------------------------------- */}
      <Tabs
        items={[
          { value: 'scans', label: 'Scans', count: filteredScans.length },
          {
            value: 'hosts',
            label: 'Hosts & ports',
            count: hosts.data?.hosts.length,
          },
          { value: 'changes', label: 'Changes', count: changes.data?.changes.length },
        ]}
      >
        <TabsContent value="scans">
          <div className="mt-4 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <label className="flex items-center gap-1.5 text-xs text-muted">
                Profile
                <select
                  value={profileFilter}
                  onChange={(event) => setProfileFilter(event.target.value)}
                  aria-label="Filter by profile"
                  className="rounded-md border border-input bg-bg px-2 py-1 text-xs text-fg outline-none focus:border-primary focus:ring-2 focus:ring-primary/25"
                >
                  <option value="all">all</option>
                  {profiles.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex items-center gap-1.5 text-xs text-muted">
                Status
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value)}
                  aria-label="Filter by status"
                  className="rounded-md border border-input bg-bg px-2 py-1 text-xs text-fg outline-none focus:border-primary focus:ring-2 focus:ring-primary/25"
                >
                  <option value="all">all</option>
                  {statuses.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <DataTable
              columns={scanColumns}
              rows={pagedScans}
              rowKey={(row) => row.id}
              loading={scans.isLoading}
              caption={`Scans of ${target?.name}`}
              emptyTitle="No scans"
              emptyDescription={
                profileFilter === 'all' && statusFilter === 'all'
                  ? 'Run one from Telegram with /scan.'
                  : 'No scans match these filters.'
              }
              emptyIcon={ScanLine}
              showColumnToggle
              multiSort
              sortSpecs={scanSort}
              onSortSpecsChange={setScanSort}
              onRowClick={(row) => {
                if (row.id === latestScan?.id) return
                setExpanded((p) => new Set(p).add(row.id))
              }}
            />

            <Pagination
              page={scanPage}
              pageSize={scanPageSize}
              total={filteredScans.length}
              onPageChange={setScanPage}
              onPageSizeChange={(size) => {
                setScanPageSize(size)
                setScanPage(1)
              }}
            />
          </div>
        </TabsContent>

        <TabsContent value="hosts">
          <div className="mt-4 space-y-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Port distribution</CardTitle>
                  {latestScan ? (
                    <span className="text-xs text-muted">
                      scan #{latestScan.id} Â· {when(latestScan.started_at)}
                    </span>
                  ) : null}
                </CardHeader>
                <CardContent>
                  {hosts.isLoading ? (
                    <Skeleton className="h-48" />
                  ) : (hosts.data?.port_distribution ?? []).length === 0 ? (
                    <EmptyState
                      icon={Network}
                      title="No open ports"
                      description="This scan found no services, or the target has not been scanned."
                    />
                  ) : (
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart
                        data={hosts.data?.port_distribution ?? []}
                        margin={{ top: 8, right: 8, left: -20, bottom: 0 }}
                      >
                        <CartesianGrid
                          stroke="rgb(var(--border))"
                          strokeDasharray="3 3"
                          vertical={false}
                        />
                        <XAxis dataKey="port" tick={AXIS_TICK} stroke="rgb(var(--border))" />
                        <YAxis
                          tick={AXIS_TICK}
                          allowDecimals={false}
                          stroke="rgb(var(--border))"
                        />
                        <RTooltip {...CHART_TOOLTIP} />
                        <Bar dataKey="count" name="hosts" radius={[4, 4, 0, 0]}>
                          {(hosts.data?.port_distribution ?? []).map((entry: PortCount) => (
                            <Cell key={entry.port} fill="rgb(var(--primary))" />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Latest scan summary</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 pt-0 text-sm">
                  {latestScan ? (
                    <>
                      <Row label="Profile" value={latestScan.profile} mono />
                      <Row label="Status" value={latestScan.status} />
                      <Row label="Started" value={whenExact(latestScan.started_at)} />
                      <Row label="Duration"
                        value={latestScan.duration_ms === null
                          ? 'â€”'
                          : `${(latestScan.duration_ms / 1000).toFixed(1)} s`} />
                      <Row label="Hosts" value={formatNumber(latestScan.host_count)} />
                      <Row
                        label="Services"
                        value={formatNumber(latestScan.service_count)}
                      />
                      {latestScan.error ? (
                        <div className="mt-2 rounded-md border border-danger/40 bg-danger-soft px-2.5 py-2 text-xs text-danger">
                          {latestScan.error}
                        </div>
                      ) : null}
                    </>
                  ) : (
                    <p className="py-6 text-center text-sm text-muted">
                      This target has not been scanned yet.
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Hosts and services</CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                {hosts.isLoading ? (
                  <TableSkeleton rows={3} cols={3} />
                ) : (hosts.data?.hosts ?? []).length === 0 ? (
                  <EmptyState
                    icon={Network}
                    title="No hosts recorded"
                    description="The latest scan found nothing, or there is no completed scan yet."
                  />
                ) : (
                  <ul className="divide-y divide-border/60">
                    {(hosts.data?.hosts ?? []).map((host: ScanHost) => {
                      const open = expanded.has(host.id)
                      return (
                        <li key={host.id}>
                          <button
                            type="button"
                            onClick={() => toggleHost(host.id)}
                            aria-expanded={open}
                            className="flex w-full items-center gap-3 py-2.5 text-left transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                          >
                            <ChevronDown
                              className={cn(
                                'h-4 w-4 shrink-0 text-muted transition-transform',
                                open && 'rotate-180',
                              )}
                              aria-hidden
                            />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate font-mono text-sm text-fg">
                                {host.address}
                              </span>
                              {host.hostname ? (
                                <span className="block truncate text-xs text-muted">
                                  {host.hostname}
                                </span>
                              ) : null}
                            </span>
                            <Badge variant={host.state === 'up' ? 'success' : 'muted'}>
                              {host.state}
                            </Badge>
                            <span className="shrink-0 text-xs text-muted">
                              {host.services.length} service(s)
                            </span>
                          </button>
                          {open ? (
                            <div className="pb-3 pl-7">
                              {host.services.length === 0 ? (
                                <p className="text-xs text-muted">No services recorded.</p>
                              ) : (
                                <table className="w-full text-left text-xs">
                                  <thead>
                                    <tr className="text-muted">
                                      <th className="py-1 font-medium">Port</th>
                                      <th className="py-1 font-medium">Proto</th>
                                      <th className="py-1 font-medium">State</th>
                                      <th className="py-1 font-medium">Service</th>
                                      <th className="py-1 font-medium">Product</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {host.services.map((svc) => (
                                      <tr key={svc.id} className="border-t border-border/60">
                                        <td className="py-1 font-mono tabular-nums text-fg">
                                          {svc.port}
                                        </td>
                                        <td className="py-1 text-muted">{svc.protocol}</td>
                                        <td className="py-1">
                                          <Badge
                                            variant={svc.state === 'open' ? 'success' : 'muted'}
                                          >
                                            {svc.state}
                                          </Badge>
                                        </td>
                                        <td className="py-1 text-fg">{svc.service_name ?? 'â€”'}</td>
                                        <td className="py-1 text-muted">
                                          {svc.product ? (
                                            <>
                                              {svc.product}
                                              {svc.version ? ` ${svc.version}` : ''}
                                            </>
                                          ) : (
                                            'â€”'
                                          )}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              )}
                            </div>
                          ) : null}
                        </li>
                      )
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="changes">
          <div className="mt-4">
            {changes.isLoading ? (
              <TableSkeleton rows={5} cols={4} />
            ) : (changes.data?.changes ?? []).length === 0 ? (
              <EmptyState
                icon={AlertTriangle}
                title="No change events"
                description="Nothing changed between scans. That is usually the healthy case."
              />
            ) : (
              <Card>
                <CardContent className="pt-4">
                  <ul className="divide-y divide-border/60">
                    {(changes.data?.changes ?? []).slice(0, 100).map((change) => (
                      <li key={change.id} className="flex items-center gap-3 py-2.5">
                        <span
                          className="h-2.5 w-2.5 shrink-0 rounded-full"
                          style={{
                            background: CHANGE_COLORS[change.change_type]
                              ?? 'rgb(var(--muted))',
                          }}
                          aria-hidden
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm text-fg">
                            <span className="font-medium">
                              {CHANGE_LABELS[change.change_type] ?? change.change_type}
                            </span>{' '}
                            <span className="font-mono text-xs text-muted">
                              {change.host}
                              {change.port !== null ? `:${change.port}` : ''}
                            </span>
                          </p>
                          {change.old_value || change.new_value ? (
                            <p className="truncate font-mono text-[11px] text-muted">
                              {change.old_value ?? 'â€”'} â†’ {change.new_value ?? 'â€”'}
                            </p>
                          ) : null}
                        </div>
                        <span className="shrink-0 text-xs text-muted">
                          {when(change.created_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                  {(changes.data?.changes ?? []).length > 100 ? (
                    <p className="mt-3 text-center text-xs text-muted">
                      Showing the 100 most recent of{' '}
                      {formatNumber(changes.data?.changes.length ?? 0)}.
                    </p>
                  ) : null}
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* --- delete confirmation -------------------------------------- */}
      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogTitle>
            Delete {target?.name} and all its history?
          </AlertDialogTitle>
          <AlertDialogDescription>
            This purges {formatNumber(target?.scan_count ?? 0)} scan(s), every host and
            service they found, and all change events. It cannot be undone, and it
            removes the security record for this target.
          </AlertDialogDescription>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => purge.mutate()}
              disabled={purge.isPending}
            >
              {purge.isPending ? 'Deletingâ€¦' : 'Delete permanently'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function Row({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}): JSX.Element {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted">{label}</span>
      <span className={cn('text-fg', mono && 'font-mono text-xs')}>{value}</span>
    </div>
  )
}