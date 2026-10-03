import * as React from 'react'
import { AlertTriangle, Inbox, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from './ui'

/* -------------------------------------------------------------------------- */
/* Skeleton                                                                   */
/* -------------------------------------------------------------------------- */

export function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-md bg-elevated',
        'before:absolute before:inset-0 before:-translate-x-full',
        'before:animate-shimmer before:bg-gradient-to-r',
        'before:from-transparent before:via-border before:to-transparent',
        className,
      )}
      {...props}
    />
  )
}

/** Placeholder matching the shape of a table body while loading. */
export function TableSkeleton({ rows = 5, cols = 5 }: { rows?: number; cols?: number }): JSX.Element {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className={cn('h-8', c === 0 ? 'w-1/4' : 'flex-1')} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function CardSkeleton({ count = 4 }: { count?: number }): JSX.Element {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} className="h-24 rounded-lg" />
      ))}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* EmptyState                                                                 */
/* -------------------------------------------------------------------------- */

export interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  description?: string
  actionLabel?: string
  onAction?: () => void
  className?: string
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  actionLabel,
  onAction,
  className,
}: EmptyStateProps): JSX.Element {
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 py-14 text-center', className)}>
      <div className="mb-3 rounded-full bg-elevated p-3">
        <Icon className="h-6 w-6 text-muted" />
      </div>
      <p className="text-sm font-medium text-fg">{title}</p>
      {description ? <p className="mt-1 max-w-sm text-sm text-muted">{description}</p> : null}
      {actionLabel && onAction ? (
        <Button className="mt-4" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      ) : null}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* ErrorState                                                                 */
/* -------------------------------------------------------------------------- */

export function ErrorState({
  title = 'Something went wrong',
  description,
  onRetry,
}: {
  title?: string
  description?: string
  onRetry?: () => void
}): JSX.Element {
  return (
    <EmptyState
      icon={AlertTriangle}
      title={title}
      description={description}
      {...(onRetry ? { actionLabel: 'Try again', onAction: onRetry } : {})}
    />
  )
}

/* -------------------------------------------------------------------------- */
/* Spinner                                                                    */
/* -------------------------------------------------------------------------- */

export function Spinner({ className }: { className?: string }): JSX.Element {
  return (
    <span
      className={cn(
        'inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent',
        className,
      )}
      role="status"
      aria-label="Loading"
    />
  )
}

/* -------------------------------------------------------------------------- */
/* StatusDot                                                                  */
/* -------------------------------------------------------------------------- */

export function StatusDot({
  ok,
  label,
}: {
  ok: boolean
  label: string
}): JSX.Element {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span
        className={cn('h-2 w-2 rounded-full', ok ? 'bg-primary' : 'bg-danger')}
        aria-hidden
      />
      <span className={ok ? 'text-fg' : 'text-danger'}>{label}</span>
    </span>
  )
}