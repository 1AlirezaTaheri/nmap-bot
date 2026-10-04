import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type ChangeRow } from '@/lib/api'
import { haptic } from '@/lib/telegram'
import { changeTone, cn, relative } from '@/lib/utils'
import { Badge, EmptyState, ErrorState, Sheet, Skeleton } from '@/components/ui'

type Filter = 'all' | 'new_host' | 'new_port' | 'service_change' | 'closed'

const FILTERS: ReadonlyArray<{ key: Filter; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'new_host', label: 'New host' },
  { key: 'new_port', label: 'New port' },
  { key: 'service_change', label: 'Service' },
  { key: 'closed', label: 'Closed' },
]

export function ChangesPage(): JSX.Element {
  const [filter, setFilter] = React.useState<Filter>('all')
  const [detail, setDetail] = React.useState<ChangeRow | null>(null)

  // "closed" is a UI convenience covering closed_host and closed_port, so it
  // is expanded client-side rather than becoming two more server filters.
  const query = useQuery({
    queryKey: ['changes', filter],
    queryFn: ({ signal }) => {
      if (filter === 'all') return api.changes({}, signal)
      if (filter === 'closed') return api.changes({}, signal)
      return api.changes({ change_type: filter }, signal)
    },
  })

  const rows = React.useMemo(() => {
    const all = query.data?.changes ?? []
    return filter === 'closed'
      ? all.filter(
          (c) => c.change_type === 'closed_port' || c.change_type === 'closed_host',
        )
      : all
  }, [query.data, filter])

  const grouped = React.useMemo(() => {
    const map = new Map<string, ChangeRow[]>()
    for (const change of rows) {
      const day = change.created_at
        ? new Date(change.created_at).toDateString()
        : 'unknown'
      const bucket = map.get(day)
      if (bucket) bucket.push(change)
      else map.set(day, [change])
    }
    return [...map.entries()]
  }, [rows])

  if (query.isError) {
    return (
      <ErrorState
        message={(query.error as Error).message}
        onRetry={() => void query.refetch()}
      />
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-1.5 overflow-x-auto pb-1">
        {FILTERS.map((option) => (
          <button
            key={option.key}
            className={cn(
              'chip shrink-0',
              filter === option.key
                ? 'bg-button text-button-text'
                : 'bg-secondary text-hint',
            )}
            onClick={() => {
              haptic()
              setFilter(option.key)
            }}
          >
            {option.label}
          </button>
        ))}
      </div>

      {query.isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          icon="✨"
          title="No changes"
          description="A scan found nothing different from the last one."
        />
      ) : (
        <div className="space-y-4">
          {grouped.map(([day, items]) => (
            <section key={day}>
              <h2 className="mb-1.5 px-1 text-[12px] font-medium uppercase tracking-wide text-hint">
                {day}
              </h2>
              <ul className="card divide-y divide-hint/10 p-0">
                {items.map((change) => {
                  const tone = changeTone(change.change_type)
                  return (
                    <li key={change.id}>
                      <button
                        className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left active:opacity-70"
                        onClick={() => {
                          haptic()
                          setDetail(change)
                        }}
                      >
                        <Badge className={tone.className}>{tone.label}</Badge>
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-mono text-[13px]">
                            {change.host}
                            {change.port ? `:${change.port}` : ''}
                          </p>
                          {change.old_value || change.new_value ? (
                            <p className="truncate text-[11px] text-hint">
                              {change.old_value ?? '—'} → {change.new_value ?? '—'}
                            </p>
                          ) : null}
                        </div>
                        <span className="shrink-0 text-[11px] text-hint">
                          {relative(change.created_at)}
                        </span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </section>
          ))}
        </div>
      )}

      <Sheet
        open={detail !== null}
        title="Change detail"
        onClose={() => setDetail(null)}
      >
        {detail ? <ChangeDetail change={detail} /> : null}
      </Sheet>
    </div>
  )
}

function ChangeDetail({ change }: { change: ChangeRow }): JSX.Element {
  const tone = changeTone(change.change_type)
  return (
    <div className="space-y-3">
      <Badge className={tone.className}>{tone.label}</Badge>
      <p className="font-mono text-[15px]">
        {change.host}
        {change.port ? `:${change.port}` : ''}
        {change.protocol ? `/${change.protocol}` : ''}
      </p>
      <dl className="space-y-2 text-[13px]">
        <div className="flex justify-between gap-3">
          <dt className="text-hint">Target</dt>
          <dd className="truncate">{change.target ?? '—'}</dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-hint">Scan</dt>
          <dd className="font-mono">#{change.scan_id}</dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-hint">When</dt>
          <dd>{relative(change.created_at)}</dd>
        </div>
        {change.old_value ? (
          <div className="flex justify-between gap-3">
            <dt className="text-hint">Was</dt>
            <dd className="truncate">{change.old_value}</dd>
          </div>
        ) : null}
        {change.new_value ? (
          <div className="flex justify-between gap-3">
            <dt className="text-hint">Now</dt>
            <dd className="truncate">{change.new_value}</dd>
          </div>
        ) : null}
      </dl>
    </div>
  )
}