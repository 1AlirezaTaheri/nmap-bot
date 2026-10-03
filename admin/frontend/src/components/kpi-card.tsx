import { ArrowDownRight, ArrowUpRight, Minus, type LucideIcon } from 'lucide-react'
import { cn, formatNumber } from '@/lib/utils'
import { Card } from './ui'
import { Skeleton } from './feedback'

export interface KPICardProps {
  label: string
  value: number | string
  icon: LucideIcon
  /** Percentage change vs the previous period; null renders flat. */
  trend?: number | null
  trendLabel?: string
  loading?: boolean
  className?: string
}

/**
 * Stat tile. The trend arrow is green when the metric went up and red when
 * it went down — the convention users expect, even though for some metrics
 * (failures) "down" is the good direction. The label says which way is good.
 */
export function KPICard({
  label,
  value,
  icon: Icon,
  trend,
  trendLabel,
  loading = false,
  className,
}: KPICardProps): JSX.Element {
  const hasTrend = typeof trend === 'number' && Number.isFinite(trend)
  const flat = hasTrend && Math.abs(trend) < 0.5
  const up = hasTrend && !flat && (trend ?? 0) > 0

  return (
    <Card className={cn('p-4', className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
          {loading ? (
            <Skeleton className="mt-2 h-8 w-20" />
          ) : (
            <p className="mt-1 text-2xl font-semibold tabular-nums text-fg">
              {typeof value === 'number' ? formatNumber(value) : value}
            </p>
          )}
        </div>
        <div className="rounded-md bg-elevated p-2">
          <Icon className="h-4 w-4 text-primary" />
        </div>
      </div>

      {hasTrend || trendLabel ? (
        <div className="mt-3 flex items-center gap-1.5 text-xs">
          {hasTrend ? (
            <span
              className={cn(
                'inline-flex items-center gap-0.5 font-medium',
                flat ? 'text-muted' : up ? 'text-primary' : 'text-danger',
              )}
            >
              {flat ? (
                <Minus className="h-3.5 w-3.5" />
              ) : up ? (
                <ArrowUpRight className="h-3.5 w-3.5" />
              ) : (
                <ArrowDownRight className="h-3.5 w-3.5" />
              )}
              {Math.abs(trend ?? 0).toFixed(0)}%
            </span>
          ) : null}
          {trendLabel ? <span className="text-muted">{trendLabel}</span> : null}
        </div>
      ) : null}
    </Card>
  )
}