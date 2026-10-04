import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  Network,
  RefreshCw,
  ScanLine,
} from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api } from '@/lib/api'
import { displayName, haptic } from '@/lib/telegram'
import { cn, formatNumber, relative } from '@/lib/utils'
import { Badge, EmptyState, ErrorState, Skeleton } from '@/components/ui'

function Kpi({
  label,
  value,
  icon,
  tone,
}: {
  label: string
  value: string
  icon: React.ReactNode
  tone: 'good' | 'bad' | 'neutral'
}): JSX.Element {
  return (
    <div className="card flex flex-col gap-1 p-3">
      <span className="text-[11px] font-medium uppercase tracking-wide text-hint">
        {label}
      </span>
      <span
        className={cn(
          'text-[22px] font-semibold tabular-nums',
          tone === 'good' && 'text-good',
          tone === 'bad' && 'text-bad',
          tone === 'neutral' && 'text-text',
        )}
      >
        {value}
      </span>
      <span className="text-hint">{icon}</span>
    </div>
  )
}

export function DashboardPage(): JSX.Element {
  const stats = useQuery({
    queryKey: ['stats'],
    queryFn: ({ signal }) => api.stats(7, signal),
  })

  const scans = useQuery({
    queryKey: ['recent-scans'],
    queryFn: async ({ signal }) => {
      const { targets } = await api.targets(signal)
      if (targets.length === 0) return []
      const per = await Promise.all(
        targets.slice(0, 8).map((t) => api.targetScans(t.id, 1, signal)),
      )
      return per
        .flatMap((r) => r.scans)
        .sort((a, b) => (b.started_at ?? '').localeCompare(a.started_at ?? ''))
        .slice(0, 5)
    },
  })

  if (stats.isError) {
    return (
      <ErrorState
        message={(stats.error as Error).message}
        onRetry={() => void stats.refetch()}
      />
    )
  }

  const data = stats.data
  const failed = (data?.scans_24h_failed ?? 0) > 0

  return (
    <div className="space-y-4">
      {/* Greeting from Telegram's own payload. Display only: the server
          re-derives identity from the signature, so a spoofed first_name
          here changes nothing but this line. */}
      <p className="text-[15px] text-hint">
        Hello, <span className="font-medium text-text">
          {displayName('there')}
        </span>
      </p>

      <div className="grid grid-cols-3 gap-2">
        {stats.isLoading ? (
          <>
            <Skeleton className="h-[86px]" />
            <Skeleton className="h-[86px]" />
            <Skeleton className="h-[86px]" />
          </>
        ) : (
          <>
            <Kpi
              label="Targets"
              value={formatNumber(data?.targets ?? 0)}
              tone="neutral"
              icon={<Network className="h-4 w-4" />}
            />
            <Kpi
              label="Scans 24h"
              value={formatNumber(data?.scans_24h ?? 0)}
              tone={failed ? 'bad' : 'good'}
              icon={
                failed ? (
                  <AlertTriangle className="h-4 w-4 text-bad" />
                ) : (
                  <ScanLine className="h-4 w-4 text-good" />
                )
              }
            />
            <Kpi
              label="Changes 24h"
              value={formatNumber(data?.changes_24h ?? 0)}
              tone={(data?.changes_24h ?? 0) > 0 ? 'neutral' : 'good'}
              icon={<AlertTriangle className="h-4 w-4" />}
            />
          </>
        )}
      </div>

      <section className="card">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-[15px] font-semibold">Last 7 days</h2>
          <button
            aria-label="Refresh"
            className="rounded p-1.5 text-hint active:opacity-60"
            onClick={() => {
              haptic()
              void stats.refetch()
              void scans.refetch()
            }}
          >
            <RefreshCw
              className={cn('h-4 w-4', stats.isFetching && 'animate-spin')}
            />
          </button>
        </div>

        {stats.isLoading ? (
          <Skeleton className="h-40" />
        ) : !data || data.series.length === 0 ? (
          <p className="py-8 text-center text-[13px] text-hint">
            No activity yet.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <LineChart
              data={data.series}
              margin={{ top: 4, right: 4, left: -24, bottom: 0 }}
            >
              <CartesianGrid stroke="rgb(var(--tg-hint))" strokeOpacity={0.15} vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10, fill: 'rgb(var(--tg-hint))' }}
                tickFormatter={(v: string) => v.slice(5)}
                stroke="rgb(var(--tg-hint))"
                strokeOpacity={0.2}
              />
              <YAxis
                tick={{ fontSize: 10, fill: 'rgb(var(--tg-hint))' }}
                allowDecimals={false}
                stroke="rgb(var(--tg-hint))"
                strokeOpacity={0.2}
              />
              <RTooltip
                contentStyle={{
                  background: 'rgb(var(--tg-secondary-bg))',
                  border: 'none',
                  borderRadius: 8,
                  fontSize: 12,
                  color: 'rgb(var(--tg-text))',
                }}
              />
              <Line
                type="monotone"
                dataKey="scans"
                name="scans"
                stroke="rgb(var(--ns-good))"
                strokeWidth={2}
                dot={{ r: 2 }}
              />
              <Line
                type="monotone"
                dataKey="changes"
                name="changes"
                stroke="rgb(var(--ns-bad))"
                strokeWidth={2}
                dot={{ r: 2 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </section>

      <section className="card">
        <h2 className="mb-2 text-[15px] font-semibold">Recent scans</h2>
        {scans.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
          </div>
        ) : (scans.data ?? []).length === 0 ? (
          <EmptyState
            icon="🛰"
            title="No scans yet"
            description="Add a target, then start your first scan."
          />
        ) : (
          <ul className="divide-y divide-hint/10">
            {(scans.data ?? []).map((scan) => (
              <li key={scan.id} className="flex items-center gap-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[14px] font-medium">
                    {scan.target ?? `scan #${scan.id}`}
                  </p>
                  <p className="text-[12px] text-hint">
                    {scan.host_count} hosts · {scan.service_count} services ·{' '}
                    {relative(scan.started_at)}
                  </p>
                </div>
                <Badge
                  className={
                    scan.status === 'succeeded'
                      ? 'bg-good-soft text-good'
                      : scan.status === 'failed'
                        ? 'bg-bad-soft text-bad'
                        : 'bg-info-soft text-info'
                  }
                >
                  {scan.status}
                </Badge>
              </li>
            ))}
          </ul>
        )}
      </section>

      <p className="pb-2 text-center text-[12px] text-hint">
        {formatNumber(data?.hosts ?? 0)} hosts ·{' '}
        {formatNumber(data?.services ?? 0)} services · last scan{' '}
        {relative(data?.last_scan_at)}
      </p>
    </div>
  )
}