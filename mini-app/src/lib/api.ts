/**
 * Typed client for the /miniapp API.
 *
 * Authentication rides in the X-Telegram-Init-Data header rather than a
 * cookie: the blob is signed by Telegram, so there is no session to steal and
 * no CSRF surface. It is read from the SDK at call time rather than captured
 * at module load, so a late initData is still picked up.
 *
 * A 401 means the signature did not verify or the session aged out. It is NOT
 * routed anywhere: the app shows "open this from Telegram" rather than
 * redirecting, because there is no login page to redirect to.
 */

import { initData, inTelegram } from './telegram'

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// --- response shapes ------------------------------------------------------

export type Role = 'viewer' | 'operator' | 'admin'

export interface Me {
  id: number
  first_name: string
  last_name: string | null
  username: string | null
  display_name: string
  photo_url: string | null
  is_premium: boolean
  language_code: string | null
  role: Role
  language: string
  notifications_enabled: boolean
  enabled: boolean
}

export interface SeriesPoint {
  date: string
  scans: number
  failed: number
  changes: number
}

export interface Stats {
  targets: number
  scans: number
  scans_24h: number
  scans_24h_failed: number
  changes: number
  changes_24h: number
  hosts: number
  services: number
  last_scan_at: string | null
  series: SeriesPoint[]
  change_breakdown: Record<string, number>
}

export interface Schedule {
  profile: string
  interval_hours: number
  enabled: boolean
  next_run_at: string | null
}

export interface Target {
  id: number
  name: string
  value: string
  group: string | null
  scan_count: number
  succeeded_count: number
  failed_count: number
  last_scan_at: string | null
  created_at: string | null
  schedule: Schedule | null
}

export interface ScanRow {
  id: number
  target: string | null
  target_value: string | null
  profile: string
  status: string
  source: string
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  host_count: number
  service_count: number
  error: string | null
  change_count: number
}

export interface ChangeRow {
  id: number
  scan_id: number
  change_type: string
  host: string
  port: number | null
  protocol: string | null
  old_value: string | null
  new_value: string | null
  created_at: string | null
  target?: string
  target_value?: string
}

export interface Rule {
  id: number
  name: string
  rule_type: string
  value: string
  priority: number
  enabled: boolean
  scope: string
  scope_id: string | null
  description: string | null
  hit_count: number
  last_hit_at: string | null
  created_at: string | null
}

export interface RuleHit {
  id: number
  rule_id: number
  target: string | null
  decision: string
  reason: string | null
  actor_id: number | null
  created_at: string | null
}

export interface RuleDecision {
  allowed: boolean
  reason: string
  rule_id: number | null
  rule_name: string | null
  effective_rate_limit_seconds: number | null
  effective_scan_timeout: number | null
  warnings: string[]
  rules_considered: number
  side_effects: string
}

// --- transport ------------------------------------------------------------

async function request<T>(path: string, options: {
  method?: 'GET' | 'POST' | 'PATCH'
  body?: unknown
  signal?: AbortSignal
} = {}): Promise<T> {
  const { method = 'GET', body, signal } = options

  const headers: Record<string, string> = {}
  const blob = initData()
  if (blob) headers['X-Telegram-Init-Data'] = blob
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  let response: Response
  try {
    response = await fetch(`/miniapp${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      ...(signal ? { signal } : {}),
    })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'Network unreachable')
  }

  if (response.status === 204) return undefined as T

  const text = await response.text()
  let parsed: unknown = null
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = null
    }
  }

  if (!response.ok) {
    const detail =
      parsed && typeof parsed === 'object' && 'detail' in parsed
        ? String((parsed as { detail: unknown }).detail)
        : `Request failed (${response.status})`
    throw new ApiError(response.status, detail)
  }

  return parsed as T
}

// --- endpoints ------------------------------------------------------------

export const api = {
  me: (signal?: AbortSignal) =>
    request<Me>('/me', signal ? { signal } : {}),

  updateSettings: (body: {
    language?: string
    notifications_enabled?: boolean
  }) => request<{ updated: Record<string, unknown> }>('/settings', {
    method: 'PATCH',
    body,
  }),

  stats: (days = 7, signal?: AbortSignal) =>
    request<Stats>(`/stats?days=${days}`, signal ? { signal } : {}),

  targets: (signal?: AbortSignal) =>
    request<{ targets: Target[]; total: number }>('/targets', signal ? { signal } : {}),

  addTarget: (body: { name: string; value: string; group?: string | null }) =>
    request<{ name: string; value: string }>('/targets', { method: 'POST', body }),

  targetScans: (id: number, limit = 10, signal?: AbortSignal) =>
    request<{ scans: ScanRow[] }>(
      `/targets/${id}/scans?limit=${limit}`,
      signal ? { signal } : {},
    ),

  targetChanges: (id: number, limit = 50, signal?: AbortSignal) =>
    request<{ changes: ChangeRow[] }>(
      `/targets/${id}/changes?limit=${limit}`,
      signal ? { signal } : {},
    ),

  startScan: (body: { target: string; profile?: string | null }) =>
    request<{
      job_id: number
      target: string
      profile: string
      state: string
    }>('/scan', { method: 'POST', body }),

  activeScan: (signal?: AbortSignal) =>
    request<{ scan: ScanRow | null }>('/scans/active', signal ? { signal } : {}),

  scan: (id: number, signal?: AbortSignal) =>
    request<{ scan: ScanRow }>(`/scans/${id}`, signal ? { signal } : {}),

  changes: (
    params: { change_type?: string; target_id?: number; page?: number } = {},
    signal?: AbortSignal,
  ) => {
    const search = new URLSearchParams()
    if (params.change_type) search.set('change_type', params.change_type)
    if (params.target_id !== undefined) search.set('target_id', String(params.target_id))
    search.set('page', String(params.page ?? 1))
    const qs = search.toString()
    return request<{
      changes: ChangeRow[]
      total: number
      page: number
      page_size: number
    }>(`/changes?${qs}`, signal ? { signal } : {})
  },

  rules: (signal?: AbortSignal) =>
    request<{ rules: Rule[]; total: number; rule_types: string[] }>(
      '/rules',
      signal ? { signal } : {},
    ),

  ruleHits: (id: number, limit = 20, signal?: AbortSignal) =>
    request<{ hits: RuleHit[]; total: number }>(
      `/rules/${id}/hits?limit=${limit}`,
      signal ? { signal } : {},
    ),

  testRules: (body: { target: string; ports?: number[]; actor_id?: number }) =>
    request<RuleDecision>('/rules/test', { method: 'POST', body }),

  profiles: (signal?: AbortSignal) =>
    request<{ profiles: string[] }>('/profiles', signal ? { signal } : {}),
}

/** Whether the app can talk to the API at all. */
export { inTelegram }