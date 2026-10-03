import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** Merge conditional class names, with later Tailwind utilities winning. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

/** Initials for the avatar circle: at most two letters. */
export function initials(value: string | null | undefined): string {
  if (!value) return '?'
  const cleaned = value.replace(/[^a-zA-Z0-9]/g, '')
  return cleaned.slice(0, 2).toUpperCase() || '?'
}

/**
 * Deterministic colour for an avatar, so a given user always gets the
 * same colour across sessions and pages.
 */
const AVATAR_COLORS = [
  'bg-emerald-500/15 text-emerald-400',
  'bg-sky-500/15 text-sky-400',
  'bg-amber-500/15 text-amber-400',
  'bg-violet-500/15 text-violet-400',
  'bg-rose-500/15 text-rose-400',
  'bg-teal-500/15 text-teal-400',
]

export function avatarColor(seed: string | number): string {
  const key = String(seed)
  let hash = 0
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0
  }
  return AVATAR_COLORS[hash % AVATAR_COLORS.length] ?? AVATAR_COLORS[0]!
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let n = bytes / 1024
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i += 1
  }
  return `${n.toFixed(1)} ${units[i]}`
}

export function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}