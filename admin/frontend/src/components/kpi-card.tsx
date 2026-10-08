import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import {
  ArrowDownRight,
  ArrowUpRight,
  Minus,
  type LucideIcon,
} from 'lucide-react'
import { cn, formatNumber } from '@/lib/utils'
import { Card, Tooltip, TooltipContent, TooltipTrigger } from './ui'
import { Skeleton } from './feedback'

export interface KPICardProps {
  label: string
  value: number | string
  icon: LucideIcon
  trend?: number | null
  trendLabel?: string
  loading?: boolean
  className?: string
  /** Longer explanation, shown in a tooltip on the label. */
  hint?: string
  /** Extra row under the value, e.g. a status line. */
  footer?: React.ReactNode
}

/** Tint applied to the icon chip, so the tile reads at a glance. */
const toneVariants = cva('rounded-md p-2', {
  variants: {
    tone: {
      neutral: 'bg-elevated text-muted',
      primary: 'bg-primary-soft text-primary',
      info: 'bg-info-soft text-info',
      warning: 'bg-warning-soft text-warning',
      danger: 'bg-danger-soft text-danger',
    },
  },
  defaultVariants: { tone: 'primary' },
})

export function KPICard({
  label,
  value,
  icon: Icon,
  trend,
  trendLabel,
  loading = false,
  className,
  hint,
  footer,
  tone,
}: KPICardProps & VariantProps<typeof toneVariants>): JSX.Element {
  const hasTrend = typeof trend === 'number' && Number.isFinite(trend)
  const flat = hasTrend && Math.abs(trend ?? 0) < 0.5
  const up = hasTrend && !flat && (trend ?? 0) > 0

  const labelNode = (
    <p className="truncate text-xs font-medium uppercase tracking-wide text-muted">
      {label}
    </p>
  )

  return (
    <Card className={cn('p-4', className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          {hint ? (
            // The trigger is the label itself, not a separate "?" affordance:
            // an extra icon is clutter for something only some readers need.
            <Tooltip>
              <TooltipTrigger asChild>{labelNode}</TooltipTrigger>
              <TooltipContent>{hint}</TooltipContent>
            </Tooltip>
          ) : (
            labelNode
          )}
          {loading ? (
            <Skeleton className="mt-2 h-8 w-20" />
          ) : (
            <p className="mt-1 text-2xl font-semibold tabular-nums text-fg">
              {typeof value === 'number' ? formatNumber(value) : value}
            </p>
          )}
        </div>
        <div className={toneVariants({ tone })}>
          <Icon className="h-4 w-4" aria-hidden />
        </div>
      </div>

      {hasTrend || trendLabel || footer ? (
        <div className="mt-3 space-y-1 text-xs">
          {hasTrend || trendLabel ? (
            <div className="flex items-center gap-1.5">
              {hasTrend ? (
                <span
                  className={cn(
                    'inline-flex items-center gap-0.5 font-medium',
                    flat ? 'text-muted' : up ? 'text-primary' : 'text-danger',
                  )}
                >
                  {flat ? (
                    <Minus className="h-3.5 w-3.5" aria-hidden />
                  ) : up ? (
                    <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
                  ) : (
                    <ArrowDownRight className="h-3.5 w-3.5" aria-hidden />
                  )}
                  {Math.abs(trend ?? 0).toFixed(0)}%
                </span>
              ) : null}
              {trendLabel ? <span className="text-muted">{trendLabel}</span> : null}
            </div>
          ) : null}
          {footer ? <div className="text-muted">{footer}</div> : null}
        </div>
      ) : null}
    </Card>
  )
}