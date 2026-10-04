import * as React from 'react'
import { cn } from '@/lib/utils'
import { haptic, onBack, setBackVisible } from '@/lib/telegram'

/* -------------------------------------------------------------------------- */
/* Badge                                                                     */
/* -------------------------------------------------------------------------- */

export function Badge({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}): JSX.Element {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium',
        className ?? 'bg-secondary text-hint',
      )}
    >
      {children}
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* Skeleton                                                                  */
/* -------------------------------------------------------------------------- */

export function Skeleton({ className }: { className?: string }): JSX.Element {
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-md bg-secondary',
        'before:absolute before:inset-0 before:-translate-x-full',
        'before:animate-shimmer before:bg-gradient-to-r',
        'before:from-transparent before:via-hint/20 before:to-transparent',
        className ?? 'h-16',
      )}
    />
  )
}

/* -------------------------------------------------------------------------- */
/* EmptyState                                                                */
/* -------------------------------------------------------------------------- */

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
}): JSX.Element {
  return (
    <div className="flex flex-col items-center px-6 py-12 text-center">
      <div className="mb-3 text-3xl opacity-70">{icon}</div>
      <p className="text-[15px] font-medium">{title}</p>
      {description ? (
        <p className="mt-1 max-w-[18rem] text-[13px] text-hint">{description}</p>
      ) : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* ErrorState                                                                */
/* -------------------------------------------------------------------------- */

export function ErrorState({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}): JSX.Element {
  return (
    <div className="flex flex-col items-center px-6 py-12 text-center">
      <div className="mb-3 text-3xl">⚠️</div>
      <p className="text-[15px] font-medium">Something went wrong</p>
      <p className="mt-1 max-w-[20rem] text-[13px] text-hint">{message}</p>
      {onRetry ? (
        <button
          className="btn-quiet mt-4 px-4 py-2 text-[14px]"
          onClick={() => {
            haptic()
            onRetry()
          }}
        >
          Try again
        </button>
      ) : null}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Sheet                                                                     */
/* -------------------------------------------------------------------------- */

interface SheetProps {
  open: boolean
  title: string
  onClose: () => void
  children: React.ReactNode
  footer?: React.ReactNode
}

/**
 * Bottom sheet, the native shape for detail and input in Telegram.
 *
 * While open it takes over Telegram's BackButton, so the hardware back
 * gesture and the on-screen button both dismiss it rather than navigating
 * the whole app back.
 */
export function Sheet({
  open,
  title,
  onClose,
  children,
  footer,
}: SheetProps): JSX.Element | null {
  React.useEffect(() => {
    if (!open) {
      setBackVisible(false)
      return
    }
    setBackVisible(true)
    const off = onBack(onClose)
    return () => {
      off()
      setBackVisible(false)
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-end">
      <button
        aria-label="Close"
        className="absolute inset-0 animate-fade-in bg-black/40"
        onClick={() => {
          haptic()
          onClose()
        }}
      />
      <div
        className="relative max-h-[85vh] w-full animate-slide-up overflow-y-auto
          rounded-t-xl bg-bg pb-4"
      >
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3
          border-b border-hint/10 bg-bg px-4 py-3">
          <h2 className="min-w-0 flex-1 truncate text-[15px] font-semibold">
            {title}
          </h2>
          <button
            aria-label="Close"
            className="-mr-1 rounded px-2 py-1 text-[14px] text-hint"
            onClick={() => {
              haptic()
              onClose()
            }}
          >
            ✕
          </button>
        </div>
        <div className="p-4">{children}</div>
        {footer ? (
          <div className="sticky bottom-0 border-t border-hint/10 bg-bg p-4">
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* SegmentedControl                                                          */
/* -------------------------------------------------------------------------- */

export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: readonly T[]
  value: T
  onChange: (value: T) => void
}): JSX.Element {
  return (
    <div className="flex gap-1 rounded-md bg-secondary p-1">
      {options.map((option) => (
        <button
          key={option}
          className={cn(
            'flex-1 rounded-sm py-1.5 text-[13px] font-medium transition-colors',
            value === option
              ? 'bg-bg text-text shadow-sm'
              : 'text-hint',
          )}
          onClick={() => {
            haptic()
            onChange(option)
          }}
        >
          {option}
        </button>
      ))}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Toggle                                                                    */
/* -------------------------------------------------------------------------- */

export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  label: string
}): JSX.Element {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className={cn(
        'relative h-7 w-12 shrink-0 rounded-full transition-colors',
        checked ? 'bg-good' : 'bg-hint/30',
      )}
      onClick={() => {
        haptic()
        onChange(!checked)
      }}
    >
      <span
        className={cn(
          'absolute top-1 h-5 w-5 rounded-full bg-white shadow transition-all',
          checked ? 'left-6' : 'left-1',
        )}
      />
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/* Sparkline                                                                 */
/* -------------------------------------------------------------------------- */

export function Sparkline({
  values,
  className,
}: {
  values: number[]
  className?: string
}): JSX.Element | null {
  if (values.length < 2) return null
  const max = Math.max(...values, 1)
  const width = 60
  const height = 18
  const step = width / (values.length - 1)
  const points = values
    .map((v, i) => `${(i * step).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`)
    .join(' ')

  return (
    <svg width={width} height={height} className={className} aria-hidden>
      <polyline
        points={points}
        fill="none"
        stroke="rgb(var(--ns-good))"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  )
}

/* -------------------------------------------------------------------------- */
/* FAB                                                                       */
/* -------------------------------------------------------------------------- */

export function Fab({ onClick, label }: { onClick: () => void; label: string }): JSX.Element {
  return (
    <button
      aria-label={label}
      className="fixed right-4 z-40 flex h-14 w-14 items-center justify-center
        rounded-full bg-button text-[26px] leading-none text-button-text
        shadow-lg active:scale-95"
      style={{ bottom: 'calc(env(safe-area-inset-bottom) + 68px)' }}
      onClick={() => {
        haptic('medium')
        onClick()
      }}
    >
      +
    </button>
  )
}