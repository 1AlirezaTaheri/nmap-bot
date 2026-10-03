# Changelog

All notable changes to NetSentinel. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
semantic versioning loosely.

## [Unreleased] — V2

### Added

**Admin service**
- A separate FastAPI application on `127.0.0.1:8080` sharing the database and
  ORM models with the bot. Login, logout, session check, password change,
  Telegram-user CRUD, audit browsing and CSV export, runtime settings,
  targets, scan history, change events and dashboard statistics.
- `admin_users` table, deliberately separate from `telegram_users`, with
  bcrypt password hashing, JWT in an HttpOnly cookie, role gates
  (`viewer`/`admin`/`superadmin`) and in-memory login throttling.
- Append-only `audit_log` recording every action from both surfaces,
  including failed logins. Audit failures are logged and swallowed so they
  can never abort the operation being audited.
- `system_settings` overrides environment config at runtime through a 5 s TTL
  cache, so changes apply without a restart. An invalid stored value falls
  back to the default instead of poisoning every read.
- Purge is superadmin-only and requires `confirm=true`; `/deltarget` is
  block-by-default.

**Bot i18n**
- `/tlang fa|en` per-user language switcher. A user's own setting wins over
  the global `bot_language`. Every bot string routes through `t()`, which
  falls back requested → `en` → the key itself. `fa` and `en` translation
  files are held to the same key count by a test.

**Frontend**
- The admin panel was rebuilt as a React 18 SPA (Vite, TypeScript `strict`,
  Tailwind, Radix, TanStack Query, Zustand, Recharts, sonner), replacing the
  server-rendered Jinja2 pages. Dark theme by default with a persisted
  light/dark toggle, green for success and primary actions, red for
  destructive ones.
- `npm run build` typechecks first, so a type error fails the image build.
  `admin/Dockerfile` builds the bundle in a `node:20-alpine` stage and ships
  only Python at runtime.

### Changed

- `bootstrap.py` mounts `admin/frontend/dist/assets` and an `/admin/*`
  catch-all that returns `index.html`, so client-side routes survive a hard
  refresh. The asset mount is registered first; if the catch-all ran first it
  would serve JavaScript as `text/html` and the browser would refuse it.
- Added `GET /api/stats/series` for the dashboard chart. All other `/api/*`
  endpoints are unchanged.
- `jinja2` dropped from `requirements.txt`; the panel no longer renders HTML
  on the server.
- `.gitignore` now excludes `node_modules`, `admin/frontend/dist` and editor
  swap files (a nano swap file of `.env` can contain its contents).

### Removed

- `admin/routes/pages.py`, `admin/templates.py`, `admin/templates/` and
  `admin/static/`.

### Fixed

- `FRONTEND_DIST` is resolved from the admin package root, not from
  `admin/services`.

### Tests

323 passing. `TestPages` was replaced by `TestSpaShell` (assets served with a
JavaScript content type, unknown routes fall through to `index.html`,
`no-store` on the shell, an actionable 503 when the build is missing) and
`TestStatsSeriesApi`.

## [Unreleased] — V1

### Added

**Scheduled monitoring**
- APScheduler (`AsyncIOScheduler`) driving recurring scans on the running
  event loop — no new external services.
- `schedules` table: target, profile, interval, enabled flag, last/next run
  timestamps.
- `/schedule list|add|remove|pause|resume|pause-all|resume-all`, operator-only.
- Pause retains configuration so `/schedule resume` needs no re-specification.
- Daily retention maintenance runs through the same scheduler.
- `operator_chats` table records the alert destination from the first `/start`,
  since a scheduled run has no originating conversation.
- Scheduled alerts are **quiet when nothing changed** — silence reads as a
  dead bot, noise trains the operator to ignore alerts.
- Graceful shutdown: scheduler stops before the worker, so nothing is left
  mid-flight.

**Retention policy**
- `RETENTION_DAYS` and `RETENTION_MAX_SCANS_PER_TARGET` limits.
- A scan is deleted only when it is outside the age window **and** not
  protected; protected means among the newest N **or** it is the newest
  successful scan.
- The newest successful scan is always retained — it is the change-detection
  baseline, and losing it would make every host look new.
- "Newest" is ordered by `started_at`, not `id`, so backfilled scans cannot
  displace a real baseline.
- Deletes in FK order: services → hosts → change_events → scans.
- `/cleanup` runs the pass on demand and reports per-table counts.

**Export and reporting**
- `/export <target> [json|csv]` sends a document. JSON is a full structured
  dump; CSV is one row per service plus one row per change event, unified by a
  `record_type` column so it stays a single spreadsheet table.
- `/report <target>` renders a 7-day summary: scan counts, success ratio,
  unique hosts and services, change events grouped by type, top 10
  most-changed hosts.

**Hardening**
- Per-target rate limiting (`RATE_LIMIT_SECONDS`), checked after
  authorization so a denied user cannot burn another target's allowance.
  A rejected attempt does not extend the window.
- Structured logging with a correlation id propagated via `contextvars`, so a
  scan spanning queue → worker thread → parser → database → Telegram can be
  traced end to end.
- `/health` reports DB connectivity, scheduler state, queue depth, active and
  pending jobs, and the last successful scan per target. It never raises.
- Input validation: target references and values capped at 255 characters;
  target names restricted to a safe character set.
- Manual and scheduled scans share one worker, so `MAX_CONCURRENT_SCANS` is a
  real ceiling rather than a per-path suggestion.
- `source` column on scans records `manual` vs `scheduled` provenance.
- Dockerfile: `tini` as PID 1 in exec form so SIGTERM reaches Python and
  APScheduler can stop cleanly; container runs as non-root.
- `docker-compose.yml`: `restart: unless-stopped` on both services, a bot
  healthcheck, `stop_grace_period: 30s`, and a named volume for logs.

**Documentation**
- README rewritten: architecture diagram, full command table, scheduled
  monitoring, retention, export/report, security notes, configuration
  reference, known limitations.
- This changelog.
- `CONTRIBUTING.md`.

### Fixed

- **Retention could delete the change-detection baseline.** Caught by tests
  written specifically to prove the invariant.
- **`get_or_create_by_value` raced.** Two worker threads scanning the same
  unseen target both read "not found" and both inserted, so the unique index
  rejected the loser and failed a scan. Now retried inside a savepoint.
- **`/deltarget` failed silently.** `Repository.delete` raised an uncaught
  `IntegrityError` and no error handler was registered, so the user saw
  nothing. Fixed with block-by-default policy, a handler-level `try/except`,
  and a global error handler that replies on any unhandled exception.
- **SQLAlchemy emitted `UPDATE scans SET target_id = NULL`** when deleting a
  target, relying on the `NOT NULL` constraint to prevent data loss. The
  dependency check now happens before any delete is attempted.
- **`/scans` raised `DetachedInstanceError`.** Rows were loaded, the session
  closed, then `s.target.name` lazily loaded. Fixed by eager-loading in the
  repository *and* making the formatter tolerate detached rows. Note that
  `getattr(obj, name, default)` does **not** help here — `DetachedInstanceError`
  is not an `AttributeError`.
- **`target_id` FK violation** when a worker passed `target_id=0`. The scan
  manager now resolves the target itself.
- **Detached `Scan` left status at `running` forever.** The row was created in
  one session and updated in another; updating a detached instance is
  silently dropped.
- **`xml_parser` looked for `<state>`** but nmap emits `<status state="up"/>`,
  so every host defaulted to `up` and down hosts leaked into the baseline.

### Security

- `.gitignore` now ignores `.env*` (whitelisting `.env.example`). Two
  token-bearing backups existed as `.env.bak-*` and were **not** ignored, so
  any `git add -A` would have committed live tokens.
- httpx logging at INFO leaked the bot token in request URLs
  (`/bot<TOKEN>/getMe`). Loggers silenced in `main.py`.

---

## [MVP]

### Added

- Telegram bot with `/start`, `/help`, `/scan`.
- Authentication via `ALLOWED_USER_IDS`, fail-closed on empty.
- Role-based authorization (viewer / operator / admin).
- Strict target validation: IP, CIDR, or hostname only; CLI options and shell
  metacharacters rejected.
- Target registry: `/addtarget`, `/targets`, `/deltarget`, `/purge`.
- Three scan profiles as fixed argument sets (quick / service / deep).
- nmap execution with `-oX` XML output, subprocess without a shell.
- XML parser and normalizer: only `open` ports, sorted, deduplicated.
- PostgreSQL persistence with the Repository pattern: models, engine/session
  manager, repositories.
- Background worker: `asyncio.Queue` with bounded concurrency, nmap pushed to
  a thread so the event loop stays responsive.
- Change detection engine, a pure module: new host, closed host, new port,
  closed port, service change.
- Telegram alerts and formatted reports.
- Scan history (`/scans`) and job status (`/status`).
- 84 tests covering the security layer, parser, pipeline, change detection,
  deletion policy and detached-instance safety.

### Notes

- Deliberately excluded: web dashboard, AI assistant, vulnerability scanning,
  topology visualisation, team support, PDF reporting. Scope is in the
  architecture brief's "What NOT to Do".
- Ports on newly discovered hosts are suppressed from `new_port` reports to
  avoid burying the signal.