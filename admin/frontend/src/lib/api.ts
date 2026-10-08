/**
 * Typed API client.
 *
 * Every call goes through `request`, which:
 *   - sends the JWT cookie (credentials: 'include');
 *   - reports the backend's `detail` string through `ApiError`, so forms can
 *     surface the server's own explanation rather than a generic failure;
 *   - calls `onUnauthorized` on a 401, EXCEPT when the call opts out.
 *
 * Why the opt-out exists: `GET /api/me` is the session probe. A 401 there is
 * the ordinary "nobody is signed in" answer, not an expired session. Firing
 * the handler for it sent the app to the login route by reloading the page,
 * which re-ran the probe and produced an unbounded reload loop. The opt-out
 * keeps "never signed in" and "signed in then lost it" distinguishable.
 */

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/** Called when a session that existed is gone. Wired up once by the router. */
let onUnauthorized: () => void = () => {}

export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  signal?: AbortSignal
  /**
   * Do not fire `onUnauthorized` on a 401. Set by the session probe, whose
   * 401 is an expected answer rather than a lost session.
   */
  suppressUnauthorized?: boolean
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, signal, suppressUnauthorized = false } = options

  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      method,
      // The JWT lives in an HttpOnly cookie, so it must ride along.
      credentials: 'include',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
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
    // Extract the server's explanation FIRST, so the 401 branch can use it
    // too. Reporting a rejected password as "Session expired" names the
    // cookie, the tunnel and the proxy, none of which are involved -- it
    // sends the operator hunting for a session bug instead of retyping.
    const detail =
      parsed && typeof parsed === 'object' && 'detail' in parsed
        ? String((parsed as { detail: unknown }).detail)
        : null

    if (response.status === 401) {
      // The session probe opts out: its 401 means "not signed in", not
      // "signed in and then lost it".
      if (!suppressUnauthorized) onUnauthorized()
      throw new ApiError(401, detail ?? 'Session expired')
    }

    throw new ApiError(
      response.status,
      detail ?? `Request failed (${response.status})`,
    )
  }

  return parsed as T
}

// ---------------------------------------------------------------------------
// Schemas — mirror the FastAPI response models.
// ---------------------------------------------------------------------------

export type Role = 'viewer' | 'admin' | 'superadmin'
export type TelegramRole = 'viewer' | 'operator' | 'admin'
export type Language = 'fa' | 'en'

export interface Me {
  id: number
  username: string
  role: Role
}

/** A login challenge from `GET /api/captcha`.
 *
 * Deliberately carries no answer field: the server never sends one. The
 * token contains only a hash of it, so this object reveals nothing a
 * script could solve without doing the arithmetic.
 */
export interface CaptchaChallenge {
  question: string
  token: string
  expires_in: number
}

export interface LoginResponse {
  username: string
  role: Role
  csrf_required: boolean
}

export interface TelegramUser {
  telegram_user_id: number
  username: string | null
  role: TelegramRole
  enabled: boolean
  /** The id also appears in ALLOWED_USER_IDS in .env. Without both this
   *  and `enabled`, the bot refuses the user at authenticate_or_denounce. */
  in_allow_list: boolean
  /** enabled AND in_allow_list: whether the bot will actually admit them. */
  effective_access: boolean
  language: Language
  timezone: string | null
  notifications_enabled: boolean
  first_seen_at: string | null
  last_seen_at: string | null
  scan_count: number
}

export interface TargetSchedule {
  id: number
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
  enabled: number
  created_at: string | null
  scan_count: number
  succeeded_count: number
  failed_count: number
  last_scan_at: string | null
  schedule: TargetSchedule | null
}

export interface ScanRow {
  id: number
  profile: string
  status: string
  source: string
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  host_count: number
  service_count: number
  error: string | null
}

export interface ChangeRow {
  id: number
  scan_id: number
  previous_scan_id: number | null
  change_type: string
  host: string
  port: number | null
  protocol: string | null
  old_value: string | null
  new_value: string | null
  created_at: string | null
}

export interface AuditEntry {
  id: number
  created_at: string | null
  actor_type: string
  actor_id: number | null
  actor_username: string | null
  action: string
  target_type: string | null
  target_id: string | null
  details: unknown
  ip_address: string | null
  success: boolean
}

export interface AuditPage {
  total: number
  page: number
  page_size: number
  entries: AuditEntry[]
}

export interface SeriesPoint {
  date: string
  scans: number
  failed: number
  changes: number
}

/** A target ranked by how much it changed in a window. */
export interface TopChangedTarget {
  id: number
  name: string
  value: string
  changes: number
  last_change_at: string | null
}

export interface TopChangedTargets {
  targets: TopChangedTarget[]
  days: number
}

/**
 * Live counters from the admin process's own scan worker.
 *
 * `available` is false when this process runs no worker, which is the normal
 * case: the bot process owns the queue and runs its own worker instance. Every
 * counter is null in that state, deliberately -- zeros would read as "idle" and
 * be wrong.
 */
export interface WorkerStatus {
  available: boolean
  running: boolean
  queue_depth: number | null
  active: number | null
  pending: number | null
  max_concurrency: number | null
}

/**
 * The scheduler switch.
 *
 * `next_run_known` is false and `next_run_at` null: nothing stores a next-run
 * time, so the dashboard reports the cadence as unknown rather than showing a
 * number derived from the interval, which would be a guess presented as data.
 */
export interface ScheduleStatus {
  enabled: boolean
  interval_hours: number | null
  next_run_at: string | null
  next_run_known: boolean
}

/* --- Target detail (Phase 3) ------------------------------------------- */

export interface TargetScheduleRow {
  id: number
  profile: string
  enabled: boolean
  interval_hours: number
  last_run_at: string | null
  next_run_at: string | null
}

export interface TargetDetail {
  id: number
  name: string
  value: string
  group: string | null
  enabled: boolean
  created_at: string | null
  scan_count: number
  schedule: TargetScheduleRow | null
}

export interface TargetTimelinePoint {
  date: string
  scans: number
  failed: number
  changes: number
}

export interface TargetTimeline {
  target_id: number
  days: number
  series: TargetTimelinePoint[]
}

export interface ScanService {
  id: number
  port: number
  protocol: string
  state: string
  service_name: string | null
  product: string | null
  version: string | null
}

export interface ScanHost {
  id: number
  address: string
  hostname: string | null
  state: string
  services: ScanService[]
}

export interface PortCount {
  port: number
  count: number
}

export interface ScanHosts {
  scan: {
    id: number
    profile: string
    status: string
    source: string
    started_at: string | null
    finished_at: string | null
    duration_ms: number | null
    host_count: number
    service_count: number
    error: string | null
  }
  hosts: ScanHost[]
  port_distribution: PortCount[]
}

export interface Stats {
  targets: number
  scans: number
  scans_24h: number
  scans_24h_failed: number
  changes: number
  changes_24h: number
  telegram_users: number
  admins: number
  hosts: number
  services: number
  last_scan_at: string | null
  series: SeriesPoint[]
  change_breakdown: Record<string, number>
  recent_audit: Array<{
    id: number
    created_at: string | null
    actor_type: string
    actor_username: string | null
    action: string
    success: boolean
  }>
  operator_chat: { chat_id: number; username: string | null } | null
}

export type SettingKind =
  | 'bool'
  | 'str'
  | `int:${string}:${string}`
  | `choice:${string}`

export interface SettingInfo {
  value: string | number | boolean
  default: string | number | boolean
  kind: SettingKind
  description: string
  updated_at: string | null
  updated_by: string | null
}

export type SettingsResponse = Record<string, SettingInfo>

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export interface AuditFilters {
  actor_id?: number
  actor_type?: string
  action?: string
  success?: boolean
  since?: string
  until?: string
  page?: number
  page_size?: number
}

/**
 * Build a query string from a filter object.
 *
 * Takes `object` rather than `Record<string, unknown>` so an interface
 * like `AuditFilters` is assignable without an index signature.
 */
function toQuery(filters: object): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === '') continue
    params.set(key, String(value))
  }
  const qs = params.toString()
  return qs ? `?${qs}` : ''
}

export const api = {
  /**
   * Fetch a login challenge.
   *
   * Called whether or not the server enforces one: a 429 here is a real
   * rate limit and is allowed to propagate, so the page can say so rather
   * than submitting a login that is certain to be refused.
   */
  captcha: (signal?: AbortSignal) =>
    request<CaptchaChallenge>('/captcha', {
      ...(signal ? { signal } : {}),
      // Same reasoning as `me`: the login page handles this itself.
      suppressUnauthorized: true,
    }),

  login: (
    username: string,
    password: string,
    captcha?: { token: string; answer: string },
  ) =>
    request<LoginResponse>('/login', {
      method: 'POST',
      body: {
        username,
        password,
        // Omitted rather than sent as null when there is no challenge:
        // the backend distinguishes 'absent' from 'wrong', and sending
        // empty strings would turn the first case into the second.
        ...(captcha ? { captcha_token: captcha.token, captcha_answer: captcha.answer } : {}),
      },
      // A 401 here means the credentials were rejected, not that a session
      // expired. Without this the handler cleared the query cache and
      // re-navigated to the login route -- the page already being viewed.
      suppressUnauthorized: true,
    }),

  logout: () => request<{ ok: boolean }>('/logout', { method: 'POST' }),

  /**
   * The session probe.
   *
   * A 401 here is the normal unauthenticated answer, so the global
   * unauthorized handler is suppressed: the caller decides what to render
   * instead. See the module docstring for why firing it caused a reload loop.
   */
  me: (signal?: AbortSignal) =>
    request<Me>('/me', {
      ...(signal ? { signal } : {}),
      suppressUnauthorized: true,
    }),

  changePassword: (password: string) =>
    request<{ ok: boolean }>('/password', { method: 'POST', body: { password } }),

  listUsers: (signal?: AbortSignal) =>
    request<{ users: TelegramUser[]; allow_list_size: number }>(
      '/telegram-users',
      signal ? { signal } : {},
    ),

  addUser: (body: {
    telegram_user_id: number
    username?: string | null
    role?: TelegramRole
    language?: Language
  }) => request<{
    telegram_user_id: number
    role: TelegramRole
    language: Language
    enabled: boolean
    in_allow_list: boolean
    effective_access: boolean
  }>(
    '/telegram-users',
    { method: 'POST', body },
  ),

  patchUser: (
    id: number,
    patch: Partial<{
      role: TelegramRole
      language: Language
      enabled: boolean
      notifications_enabled: boolean
      timezone: string | null
    }>,
  ) =>
    request<{ telegram_user_id: number; role: TelegramRole; language: Language; enabled: boolean }>(
      `/telegram-users/${id}`,
      { method: 'PATCH', body: patch },
    ),

  deleteUser: (id: number) =>
    request<{ ok: boolean }>(`/telegram-users/${id}?confirm=true`, {
      method: 'DELETE',
    }),

  audit: (filters: AuditFilters, signal?: AbortSignal) =>
    request<AuditPage>(`/audit${toQuery(filters)}`, signal ? { signal } : {}),

  auditCsvUrl: (filters: AuditFilters) => `/api/audit/export.csv${toQuery(filters)}`,

  getSettings: (signal?: AbortSignal) =>
    request<{ settings: SettingsResponse }>('/settings', signal ? { signal } : {}),

  patchSettings: (values: Record<string, string>) =>
    request<{ settings: Record<string, unknown> }>('/settings', {
      method: 'PATCH',
      body: { values },
    }),

  /** One target's identity, counts and schedule. */
  target: (id: number, signal?: AbortSignal) =>
    request<TargetDetail>(`/targets/${id}`, signal ? { signal } : {}),

  /** Daily scan and change counts for one target. */
  targetTimeline: (id: number, days = 30, signal?: AbortSignal) =>
    request<TargetTimeline>(
      `/targets/${id}/timeline?days=${days}`,
      signal ? { signal } : {},
    ),

  /** Hosts, services and port distribution for one scan. */
  scanHosts: (targetId: number, scanId: number, signal?: AbortSignal) =>
    request<ScanHosts>(
      `/targets/${targetId}/scans/${scanId}/hosts`,
      signal ? { signal } : {},
    ),

  listTargets: (signal?: AbortSignal) =>
    request<{ targets: Target[] }>('/targets', signal ? { signal } : {}),

  addTarget: (body: { name: string; value: string; group?: string | null }) =>
    request<{ name: string; value: string }>('/targets', { method: 'POST', body }),

  deleteTarget: (id: number, confirm: boolean) =>
    request<{ purged: string; counts: Record<string, number> }>(
      `/targets/${id}?confirm=${confirm ? 'true' : 'false'}`,
      { method: 'DELETE' },
    ),

  // `limit` comes AFTER `signal`, which reads oddly. Putting it before would
  // silently break every existing caller that passes an AbortSignal in second
  // position -- which is exactly what happened the first time. The order is
  // load-bearing; leave it alone.
  targetScans: (id: number, signal?: AbortSignal, limit?: number) =>
    request<{ scans: ScanRow[] }>(
      `/targets/${id}/scans${limit === undefined ? '' : `?limit=${limit}`}`,
      signal ? { signal } : {},
    ),

  targetChanges: (id: number, signal?: AbortSignal, limit?: number) =>
    request<{ changes: ChangeRow[] }>(
      `/targets/${id}/changes${limit === undefined ? '' : `?limit=${limit}`}`,
      signal ? { signal } : {},
    ),

  /** Targets with the most change events in a window, worst first. */
  topTargets: (days = 7, signal?: AbortSignal) =>
    request<TopChangedTargets>(
      `/stats/top-targets?days=${days}`,
      signal ? { signal } : {},
    ),

  /** Live worker counters. Does not throw when no worker is present. */
  workerStatus: (signal?: AbortSignal) =>
    request<WorkerStatus>('/stats/worker', signal ? { signal } : {}),

  /** The scheduler switch and interval. */
  scheduleStatus: (signal?: AbortSignal) =>
    request<ScheduleStatus>('/stats/schedule', signal ? { signal } : {}),

  stats: (days = 7, signal?: AbortSignal) =>
    request<Stats>(`/stats?days=${days}`, signal ? { signal } : {}),

  health: (signal?: AbortSignal) =>
    request<{ status: string; database: string }>('/health', signal ? { signal } : {}),
}