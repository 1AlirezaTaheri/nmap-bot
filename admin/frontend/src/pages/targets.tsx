import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { formatDistanceToNow } from 'date-fns'
import {
  AlertTriangle,
  LayoutGrid,
  PlusCircle,
  Rows3,
  Trash2,
  X,
} from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import { api, type Target } from '@/lib/api'
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  FieldError,
} from '@/components/ui'
import { Skeleton, Spinner } from '@/components/feedback'
import { DataTable, type Column } from '@/components/data-table'

const schema = z.object({
  name: z
    .string()
    .min(1, 'Required')
    .max(64, 'Max 64 characters')
    .regex(/^[A-Za-z0-9._-]+$/, 'Letters, digits, dot, dash and underscore only')
    .refine((v) => !v.startsWith('.') && !v.endsWith('.'), 'Cannot start or end with a dot'),
  value: z
    .string()
    .min(1, 'Required')
    .max(255, 'Max 255 characters')
    .refine((v) => !v.startsWith('-'), 'Cannot start with a dash')
    .refine((v) => !/[;&|<>$`\\"'*?[\]{}#~%\s]/.test(v), 'Contains rejected characters'),
  group: z.string().max(64).optional(),
})

type FormValues = z.infer<typeof schema>

/** Tiny inline sparkline; no chart library needed for four points. */
function Sparkline({ values }: { values: number[] }): JSX.Element | null {
  if (values.length < 2) return null
  const max = Math.max(...values, 1)
  const width = 64
  const height = 18
  const step = width / (values.length - 1)
  const points = values
    .map((value, index) => `${(index * step).toFixed(1)},${(height - (value / max) * height).toFixed(1)}`)
    .join(' ')

  return (
    <svg width={width} height={height} aria-hidden className="overflow-visible">
      <polyline
        points={points}
        fill="none"
        stroke="rgb(var(--primary))"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  )
}

export function TargetsPage(): JSX.Element {
  const queryClient = useQueryClient()
  const [view, setView] = React.useState<'grid' | 'table'>('grid')
  const [addOpen, setAddOpen] = React.useState(false)
  const [drawerTarget, setDrawerTarget] = React.useState<Target | null>(null)
  const [purgeTarget, setPurgeTarget] = React.useState<Target | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: ({ signal }) => api.listTargets(signal),
  })

  const create = useMutation({
    mutationFn: api.addTarget,
    onSuccess: () => {
      toast.success('Target added')
      setAddOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['targets'] })
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not add target'),
  })

  const purge = useMutation({
    mutationFn: (id: number) => api.deleteTarget(id, true),
    onSuccess: (result) => {
      toast.success(`Purged ${result.purged}`, {
        description: `${result.counts.scans} scans, ${result.counts.hosts} hosts, ${result.counts.services} services removed`,
      })
      setPurgeTarget(null)
      setDrawerTarget(null)
      void queryClient.invalidateQueries({ queryKey: ['targets'] })
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Purge failed'),
  })

  const targets = data?.targets ?? []

  const columns: Column<Target>[] = [
    {
      key: 'name',
      header: 'Name',
      sortable: true,
      sortValue: (t) => t.name,
      cell: (t) => (
        <button
          className="text-sm font-medium text-fg hover:text-primary"
          onClick={(event) => {
            event.stopPropagation()
            setDrawerTarget(t)
          }}
        >
          {t.name}
        </button>
      ),
    },
    {
      key: 'value',
      header: 'Value',
      cell: (t) => <span className="font-mono text-xs text-muted">{t.value}</span>,
    },
    {
      key: 'scans',
      header: 'Scans',
      sortable: true,
      sortValue: (t) => t.scan_count,
      className: 'text-right tabular-nums',
      cell: (t) => formatNumber(t.scan_count),
    },
    {
      key: 'health',
      header: 'OK / failed',
      className: 'text-right',
      cell: (t) => (
        <span className="flex items-center justify-end gap-1">
          <Badge variant="success">{t.succeeded_count}</Badge>
          {t.failed_count > 0 ? <Badge variant="danger">{t.failed_count}</Badge> : null}
        </span>
      ),
    },
    {
      key: 'last',
      header: 'Last scan',
      sortable: true,
      sortValue: (t) => t.last_scan_at ?? '',
      cell: (t) => (
        <span className="text-xs text-muted">
          {t.last_scan_at ? formatDistanceToNow(new Date(t.last_scan_at), { addSuffix: true }) : 'never'}
        </span>
      ),
    },
    {
      key: 'schedule',
      header: 'Schedule',
      cell: (t) =>
        t.schedule ? (
          <span className="flex items-center gap-1.5 text-xs">
            <Badge variant={t.schedule.enabled ? 'success' : 'warning'}>
              {t.schedule.enabled ? 'on' : 'paused'}
            </Badge>
            <span className="text-muted">
              {t.schedule.profile}/{t.schedule.interval_hours}h
            </span>
          </span>
        ) : (
          <Badge variant="muted">none</Badge>
        ),
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => setAddOpen(true)}>
          <PlusCircle className="h-4 w-4" />
          Add target
        </Button>
        <div className="ml-auto flex rounded-md border border-border p-0.5">
          <button
            className={cn(
              'flex items-center gap-1.5 rounded px-2.5 py-1 text-xs transition-colors',
              view === 'grid' ? 'bg-primary text-primary-fg' : 'text-muted hover:text-fg',
            )}
            onClick={() => setView('grid')}
          >
            <LayoutGrid className="h-3.5 w-3.5" /> Grid
          </button>
          <button
            className={cn(
              'flex items-center gap-1.5 rounded px-2.5 py-1 text-xs transition-colors',
              view === 'table' ? 'bg-primary text-primary-fg' : 'text-muted hover:text-fg',
            )}
            onClick={() => setView('table')}
          >
            <Rows3 className="h-3.5 w-3.5" /> Table
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-40 rounded-lg" />
          ))}
        </div>
      ) : targets.length === 0 ? (
        <div className="card">
          <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <div className="mb-3 rounded-full bg-elevated p-3">
              <AlertTriangle className="h-6 w-6 text-muted" />
            </div>
            <p className="text-sm font-medium text-fg">No targets yet</p>
            <p className="mt-1 max-w-sm text-sm text-muted">
              Add a target so the bot knows what to scan.
            </p>
            <Button className="mt-4" size="sm" onClick={() => setAddOpen(true)}>
              Add target
            </Button>
          </div>
        </div>
      ) : view === 'grid' ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {targets.map((target) => (
            <div key={target.id} className="card p-4 transition-colors hover:border-primary/40">
              <div className="flex items-start justify-between gap-2">
                <button
                  className="min-w-0 text-left"
                  onClick={() => setDrawerTarget(target)}
                >
                  <p className="truncate text-sm font-semibold text-fg">{target.name}</p>
                  <p className="truncate font-mono text-xs text-muted">{target.value}</p>
                </button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 shrink-0 text-muted hover:text-danger"
                  aria-label={`Purge ${target.name}`}
                  onClick={() => setPurgeTarget(target)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>

              <div className="mt-4 flex items-end justify-between">
                <div>
                  <p className="text-2xl font-semibold tabular-nums text-fg">
                    {formatNumber(target.scan_count)}
                  </p>
                  <p className="text-xs text-muted">scans</p>
                </div>
                <Sparkline values={[target.succeeded_count, target.scan_count]} />
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-1.5 text-xs">
                {target.schedule ? (
                  <Badge variant={target.schedule.enabled ? 'success' : 'warning'}>
                    {target.schedule.profile} · {target.schedule.interval_hours}h
                  </Badge>
                ) : (
                  <Badge variant="muted">no schedule</Badge>
                )}
                <span className="ml-auto text-muted">
                  {target.last_scan_at
                    ? formatDistanceToNow(new Date(target.last_scan_at), { addSuffix: true })
                    : 'never scanned'}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <DataTable
          columns={columns}
          rows={targets}
          rowKey={(t) => t.id}
          onRowClick={(t) => setDrawerTarget(t)}
          sortKey="name"
          sortDirection="asc"
          onSortChange={() => undefined}
        />
      )}

      <AddTargetDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        pending={create.isPending}
        onSubmit={(values) => create.mutate(values)}
      />

      {drawerTarget ? (
        <TargetDrawer
          target={drawerTarget}
          onClose={() => setDrawerTarget(null)}
          onPurge={() => setPurgeTarget(drawerTarget)}
        />
      ) : null}

      <PurgeDialog
        target={purgeTarget}
        pending={purge.isPending}
        onOpenChange={(open) => {
          if (!open) setPurgeTarget(null)
        }}
        onConfirm={(id) => purge.mutate(id)}
      />
    </div>
  )
}

function AddTargetDialog({
  open,
  onOpenChange,
  pending,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  pending: boolean
  onSubmit: (values: FormValues) => void
}): JSX.Element {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { name: '', value: '', group: '' },
  })

  React.useEffect(() => {
    if (!open) reset()
  }, [open, reset])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add target</DialogTitle>
          <DialogDescription>
            Validated by the same parser the bot uses, and subject to the same scope rules.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            void handleSubmit((values) => onSubmit({
              name: values.name,
              value: values.value,
              ...(values.group ? { group: values.group } : {}),
            }))(event)
          }}
          noValidate
        >
          <div>
            <Label htmlFor="t-name">Name</Label>
            <Input id="t-name" placeholder="home" {...register('name')} />
            <FieldError>{errors.name?.message}</FieldError>
          </div>
          <div>
            <Label htmlFor="t-value">Value</Label>
            <Input id="t-value" placeholder="192.168.174.0/24" {...register('value')} />
            <FieldError>{errors.value?.message}</FieldError>
          </div>
          <div>
            <Label htmlFor="t-group">Group (optional)</Label>
            <Input id="t-group" placeholder="core" {...register('group')} />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? <Spinner /> : null}
              Add target
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function TargetDrawer({
  target,
  onClose,
  onPurge,
}: {
  target: Target
  onClose: () => void
  onPurge: () => void
}): JSX.Element {
  const scans = useQuery({
    queryKey: ['target-scans', target.id],
    queryFn: ({ signal }) => api.targetScans(target.id, signal),
  })
  const changes = useQuery({
    queryKey: ['target-changes', target.id],
    queryFn: ({ signal }) => api.targetChanges(target.id, signal),
  })

  React.useEffect(() => {
    function onKey(event: KeyboardEvent): void {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <button className="flex-1 cursor-default bg-black/50 backdrop-blur-sm" aria-label="Close" onClick={onClose} />
      <aside className="flex w-full max-w-lg flex-col border-l border-border bg-surface shadow-2xl animate-slide-in-right">
        <header className="flex items-start justify-between gap-3 border-b border-border p-4">
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-fg">{target.name}</h2>
            <p className="truncate font-mono text-xs text-muted">{target.value}</p>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </Button>
        </header>

        <div className="flex-1 space-y-5 overflow-y-auto p-4">
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
              Scan history
            </h3>
            {scans.isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : (scans.data?.scans ?? []).length === 0 ? (
              <p className="text-sm text-muted">No scans recorded.</p>
            ) : (
              <ul className="space-y-1.5">
                {scans.data?.scans.map((scan) => (
                  <li
                    key={scan.id}
                    className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 text-xs"
                  >
                    <span className="font-mono text-muted">#{scan.id}</span>
                    <span className="flex items-center gap-1.5">
                      {scan.source === 'scheduled' ? <Badge variant="info">scheduled</Badge> : null}
                      <Badge variant={scan.status === 'succeeded' ? 'success' : scan.status === 'failed' ? 'danger' : 'muted'}>
                        {scan.status}
                      </Badge>
                    </span>
                    <span className="tabular-nums text-muted">
                      {scan.host_count}h / {scan.service_count}s
                    </span>
                    <span className="text-muted">
                      {scan.duration_ms != null ? `${(scan.duration_ms / 1000).toFixed(1)}s` : '—'}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
              Change events
            </h3>
            {changes.isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-8" />
                ))}
              </div>
            ) : (changes.data?.changes ?? []).length === 0 ? (
              <p className="text-sm text-muted">No change events recorded.</p>
            ) : (
              <ul className="space-y-1.5">
                {changes.data?.changes.map((change) => (
                  <li
                    key={change.id}
                    className="flex items-start justify-between gap-3 rounded-md border border-border px-3 py-2 text-xs"
                  >
                    <span className="min-w-0">
                      <span className="font-mono text-fg">
                        {change.host}
                        {change.port ? `:${change.port}` : ''}
                      </span>
                      {change.old_value || change.new_value ? (
                        <span className="mt-0.5 block text-muted">
                          {change.old_value ?? '—'} → {change.new_value ?? '—'}
                        </span>
                      ) : null}
                    </span>
                    <Badge
                      variant={
                        change.change_type === 'new_host' || change.change_type === 'new_port'
                          ? 'success'
                          : change.change_type === 'closed_port' || change.change_type === 'closed_host'
                            ? 'danger'
                            : 'warning'
                      }
                    >
                      {change.change_type.replace(/_/g, ' ')}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <footer className="border-t border-border p-4">
          <Button variant="danger" className="w-full" onClick={onPurge}>
            <Trash2 className="h-4 w-4" />
            Purge target and history
          </Button>
        </footer>
      </aside>
    </div>
  )
}

function PurgeDialog({
  target,
  pending,
  onOpenChange,
  onConfirm,
}: {
  target: Target | null
  pending: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (id: number) => void
}): JSX.Element {
  const [typed, setTyped] = React.useState('')

  React.useEffect(() => {
    setTyped('')
  }, [target?.id])

  // Typing the exact name is the guard: a stray click must not wipe history.
  const confirmed = target !== null && typed === target.name

  return (
    <AlertDialog open={target !== null} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogTitle className="text-danger">Purge {target?.name}?</AlertDialogTitle>
        <AlertDialogDescription>
          This permanently deletes the target and <strong>all</strong> of its scan history,
          including hosts, services and change events. It cannot be undone.
        </AlertDialogDescription>

        <div className="mt-4">
          <Label htmlFor="confirm-name">
            Type <span className="font-mono text-fg">{target?.name}</span> to confirm
          </Label>
          <Input
            id="confirm-name"
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
            placeholder={target?.name}
            autoComplete="off"
          />
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel asChild>
            <Button variant="outline" disabled={pending}>
              Cancel
            </Button>
          </AlertDialogCancel>
          <AlertDialogAction asChild>
            <Button
              variant="danger"
              disabled={!confirmed || pending || target === null}
              onClick={(event) => {
                // Prevent Radix from closing before the mutation resolves.
                event.preventDefault()
                if (target && confirmed) onConfirm(target.id)
              }}
            >
              {pending ? <Spinner /> : null}
              Purge permanently
            </Button>
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}