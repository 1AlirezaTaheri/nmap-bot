import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Play, Search } from 'lucide-react'
import { api, type Target } from '@/lib/api'
import { haptic, toast } from '@/lib/telegram'
import { changeTone, relative } from '@/lib/utils'
import {
  Badge,
  EmptyState,
  ErrorState,
  Fab,
  Sheet,
  Skeleton,
} from '@/components/ui'

export function TargetsPage(): JSX.Element {
  const queryClient = useQueryClient()
  const [search, setSearch] = React.useState('')
  const [open, setOpen] = React.useState(false)
  const [detail, setDetail] = React.useState<Target | null>(null)

  const targets = useQuery({
    queryKey: ['targets'],
    queryFn: ({ signal }) => api.targets(signal),
  })

  const create = useMutation({
    mutationFn: api.addTarget,
    onSuccess: (created) => {
      toast(`Added ${created.name}`)
      setOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['targets'] })
    },
    onError: (error) => toast((error as Error).message),
  })

  const needle = search.trim().toLowerCase()
  const all = targets.data?.targets ?? []
  const filtered = needle
    ? all.filter((t) => `${t.name} ${t.value}`.toLowerCase().includes(needle))
    : all

  if (targets.isError) {
    return (
      <ErrorState
        message={(targets.error as Error).message}
        onRetry={() => void targets.refetch()}
      />
    )
  }

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-hint" />
        <input
          className="input pl-9"
          placeholder="Search targets"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      {targets.isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon="🛰"
          title={all.length === 0 ? 'Add your first target' : 'No matches'}
          description={
            all.length === 0
              ? 'A target is a network or host the bot is allowed to scan.'
              : 'Try a different search.'
          }
        />
      ) : (
        <ul className="space-y-2">
          {filtered.map((target) => (
            <li key={target.id}>
              <button
                className="card w-full text-left active:opacity-70"
                onClick={() => {
                  haptic()
                  setDetail(target)
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-[15px] font-semibold">
                      {target.name}
                    </p>
                    <p className="truncate font-mono text-[13px] text-hint">
                      {target.value}
                    </p>
                  </div>
                  <Badge className="bg-secondary text-hint">
                    {target.scan_count} scans
                  </Badge>
                </div>

                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  {target.schedule ? (
                    <Badge
                      className={
                        target.schedule.enabled
                          ? 'bg-good-soft text-good'
                          : 'bg-warn-soft text-warn'
                      }
                    >
                      {target.schedule.enabled ? 'scheduled' : 'paused'} ·{' '}
                      {target.schedule.interval_hours}h
                    </Badge>
                  ) : (
                    <Badge className="bg-secondary text-hint">no schedule</Badge>
                  )}
                  {target.failed_count > 0 ? (
                    <Badge className="bg-bad-soft text-bad">
                      {target.failed_count} failed
                    </Badge>
                  ) : null}
                  <span className="ml-auto text-[12px] text-hint">
                    {relative(target.last_scan_at)}
                  </span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}

      <Fab label="Add target" onClick={() => setOpen(true)} />

      <AddTargetSheet
        open={open}
        pending={create.isPending}
        onClose={() => setOpen(false)}
        onSubmit={(body) => create.mutate(body)}
      />

      {detail ? (
        <TargetSheet target={detail} onClose={() => setDetail(null)} />
      ) : null}
    </div>
  )
}

function AddTargetSheet({
  open,
  pending,
  onClose,
  onSubmit,
}: {
  open: boolean
  pending: boolean
  onClose: () => void
  onSubmit: (body: { name: string; value: string }) => void
}): JSX.Element {
  const [name, setName] = React.useState('')
  const [value, setValue] = React.useState('')
  const [error, setError] = React.useState<string | null>(null)

  // Clear the form when the sheet reopens, so a previous attempt does not
  // linger behind the new one.
  React.useEffect(() => {
    if (open) {
      setName('')
      setValue('')
      setError(null)
    }
  }, [open])

  function submit(): void {
    if (!name.trim()) {
      setError('Give the target a name.')
      return
    }
    if (!value.trim()) {
      setError('Give the target an address or CIDR.')
      return
    }
    haptic()
    onSubmit({ name: name.trim(), value: value.trim() })
  }

  return (
    <Sheet
      open={open}
      title="Add target"
      onClose={onClose}
      footer={
        <button className="btn-primary" onClick={submit} disabled={pending}>
          {pending ? 'Adding…' : 'Add target'}
        </button>
      }
    >
      <div className="space-y-3">
        <div>
          <label className="mb-1 block text-[13px] text-hint" htmlFor="t-name">
            Name
          </label>
          <input
            id="t-name"
            className="input"
            placeholder="home"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <label className="mb-1 block text-[13px] text-hint" htmlFor="t-value">
            Address or CIDR
          </label>
          <input
            id="t-value"
            className="input font-mono"
            placeholder="192.168.1.0/24"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        {error ? <p className="text-[13px] text-bad">{error}</p> : null}
        <p className="text-[12px] text-hint">
          The same validation and scope rules apply as in chat: a target
          outside your allowed ranges is refused.
        </p>
      </div>
    </Sheet>
  )
}

function TargetSheet({
  target,
  onClose,
}: {
  target: Target
  onClose: () => void
}): JSX.Element {
  const scans = useQuery({
    queryKey: ['target-scans', target.id],
    queryFn: ({ signal }) => api.targetScans(target.id, 10, signal),
  })

  const changes = useQuery({
    queryKey: ['target-changes', target.id],
    queryFn: ({ signal }) => api.targetChanges(target.id, 20, signal),
  })

  const scan = useMutation({
    mutationFn: () => api.startScan({ target: target.name }),
    onSuccess: (result) => {
      haptic('success')
      toast(`Queued a ${result.profile} scan of ${result.target}`)
    },
    onError: (error) => {
      haptic('error')
      toast((error as Error).message)
    },
  })

  return (
    <Sheet open title={target.name} onClose={onClose}>
      <div className="space-y-4">
        <p className="font-mono text-[13px] text-hint">{target.value}</p>

        <section>
          <h3 className="mb-2 text-[14px] font-semibold">Scan history</h3>
          {scans.isLoading ? (
            <Skeleton className="h-16" />
          ) : (scans.data?.scans ?? []).length === 0 ? (
            <p className="text-[13px] text-hint">No scans yet.</p>
          ) : (
            <ul className="divide-y divide-hint/10">
              {(scans.data?.scans ?? []).map((scan) => (
                <li key={scan.id} className="flex items-center gap-2 py-2">
                  <span className="font-mono text-[12px] text-hint">
                    #{scan.id}
                  </span>
                  <span className="text-[13px]">
                    {scan.host_count}h / {scan.service_count}s
                  </span>
                  <span className="ml-auto text-[12px] text-hint">
                    {relative(scan.started_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 className="mb-2 text-[14px] font-semibold">Recent changes</h3>
          {changes.isLoading ? (
            <Skeleton className="h-16" />
          ) : (changes.data?.changes ?? []).length === 0 ? (
            <p className="text-[13px] text-hint">No change events.</p>
          ) : (
            <ul className="space-y-1.5">
              {(changes.data?.changes ?? []).slice(0, 10).map((change) => {
                const tone = changeTone(change.change_type)
                return (
                  <li key={change.id} className="flex items-center gap-2">
                    <Badge className={tone.className}>{tone.label}</Badge>
                    <span className="min-w-0 flex-1 truncate font-mono text-[12px]">
                      {change.host}
                      {change.port ? `:${change.port}` : ''}
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        <button
          className="btn-primary w-full"
          disabled={scan.isPending}
          onClick={() => scan.mutate()}
        >
          <Play className="h-4 w-4" />
          {scan.isPending ? 'Queueing…' : 'Scan now'}
        </button>

        <p className="text-[12px] text-hint">
          Renaming, rescheduling and deleting a target are done in the web
          panel. Everything else — including the scan above — goes through the
          same rules as a <span className="font-mono">/scan</span> in chat.
        </p>
      </div>
    </Sheet>
  )
}