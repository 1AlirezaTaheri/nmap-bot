import { clsx, type ClassValue } from 'clsx'
import { formatDistanceToNow } from 'date-fns'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

/** "2h ago", or "never" for a missing timestamp. */
export function relative(value: string | null | undefined): string {
  if (!value) return 'never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'never'
  return formatDistanceToNow(date, { addSuffix: true })
}

export function absolute(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

/** Elapsed time as m:ss, for a running scan. */
export function elapsed(since: string | null | undefined): string {
  if (!since) return '0:00'
  const start = new Date(since).getTime()
  if (Number.isNaN(start)) return '0:00'
  const seconds = Math.max(0, Math.floor((Date.now() - start) / 1000))
  const minutes = Math.floor(seconds / 60)
  return `${minutes}:${String(seconds % 60).padStart(2, '0')}`
}

/**
 * Presentation for each change type.
 *
 * Tone is deliberately semantic rather than Telegram's palette: a closed port
 * has to read as a loss and a new host as a gain.
 */
export const CHANGE_TONE: Record<
  string,
  { label: string; className: string }
> = {
  new_host: { label: 'New host', className: 'bg-good-soft text-good' },
  new_port: { label: 'New port', className: 'bg-info-soft text-info' },
  service_change: { label: 'Service', className: 'bg-warn-soft text-warn' },
  closed_port: { label: 'Closed', className: 'bg-bad-soft text-bad' },
  closed_host: { label: 'Gone', className: 'bg-secondary text-hint' },
}

export function changeTone(changeType: string): { label: string; className: string } {
  return (
    CHANGE_TONE[changeType] ?? {
      label: changeType,
      className: 'bg-secondary text-hint',
    }
  )
}

export function scanStatusTone(status: string): string {
  if (status === 'succeeded') return 'bg-good-soft text-good'
  if (status === 'failed') return 'bg-bad-soft text-bad'
  return 'bg-info-soft text-info'
}

/** HH:MM-HH:MM is the shape the rule engine expects, for the test sheet. */
export function isTimeWindow(value: string): boolean {
  return /^\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2}$/.test(value.trim())
}