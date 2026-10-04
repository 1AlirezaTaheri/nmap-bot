# NetSentinel

**Network Intelligence & Security Monitoring Assistant** — know what is on
your network, what changed, and what deserves your attention.

A Telegram bot that runs nmap, stores normalized results in PostgreSQL,
and reports *differences* between scans rather than raw dumps.

---

## Architecture

```
                    ┌──────────────────────────────┐
                    │           User               │
                    │      Telegram  /scan         │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │   security/                  │
                    │  authenticate → authorize    │
                    │  → target scope check        │
                    │  → rate limit                │
                    └───────────────┬──────────────┘
                                    │
             ┌──────────────────────▼───────────────────────┐
             │            workers/scan_worker.py            │
             │   single queue · bounded concurrency        │
             │   manual + scheduled share one worker        │
             └───┬───────────────────────────────┬──────────┘
                 │                               │
   ┌─────────────▼──────────────┐   ┌────────────▼───────────────┐
   │  core/scheduler.py         │   │  core/scan_manager.py       │
   │  APScheduler               │   │  (Facade over the pipeline) │
   │  • per-target schedules    │   └────────────┬───────────────┘
   │  • daily retention         │                │
   └─────────────┬──────────────┘                │
                 │                  ┌─────────────▼─────────────┐
                 │                  │  parser/                  │
                 │                  │  nmap -oX → xml_parser     │
                 │                  │  → normalizer             │
                 │                  └─────────────┬─────────────┘
                 │                                │
                 │                  ┌─────────────▼─────────────┐
                 │                  │  database/  (PostgreSQL)  │
                 │                  │  models + repository      │
                 │                  └─────────────┬─────────────┘
                 │                                │
                 │                  ┌─────────────▼─────────────┐
                 └──────────────────►│  core/change_detector.py  │
                    alert on change │  pure diff, no DB/Telegram │
                                       └─────────────────────────┘

Scheduled alerts → operator chat (remembered from /start)
```

### Pipeline

1. **Authenticate** — the caller's Telegram ID must be in `ALLOWED_USER_IDS`.
2. **Authorize** — role check, then target scope check.
3. **Rate limit** — at most one scan per target per `RATE_LIMIT_SECONDS`.
4. **Queue** — the job goes onto an `asyncio.Queue`; the handler returns
   immediately, so the bot stays responsive.
5. **Execute** — a worker thread runs nmap with XML output.
6. **Parse & normalize** — only `open` ports are kept, addresses lowercased,
   ports sorted, strings whitespace-normalized.
7. **Persist** — scan, hosts, services written in one transaction.
8. **Detect** — diff against the last successful scan of the same
   target+profile. This module is *pure*: no database, no Telegram.
9. **Alert** — completion message plus a change report.

---

## Commands

| Command | Role | Purpose |
| --- | --- | --- |
| `/start` | any | Greet; records the chat for scheduled alerts |
| `/help` | any | Command reference |
| `/addtarget <name> <value> [group]` | operator | Register a target |
| `/targets` | any | List targets |
| `/deltarget <name>` | operator | Delete a target with no history |
| `/purge <name> confirm` | operator | Delete a target **and** all history |
| `/scan <target\|name> [profile]` | operator | Queue a scan |
| `/scans <name>` | any | Scan history |
| `/status` | any | Active/queued scans |
| `/health` | any | DB, scheduler, queue, last successful scan |
| `/cleanup` | operator | Run retention now |
| `/export <target> [json\|csv]` | any | Export recent scans as a document |
| `/report <target>` | any | 7-day human-readable summary |
| `/schedule list` | operator | Show schedules and next run time |
| `/schedule add <target> <profile> <hours>` | operator | Create/replace a schedule |
| `/schedule remove <target>` | operator | Delete a schedule |
| `/schedule pause <target>` | operator | Pause (config retained) |
| `/schedule resume <target>` | operator | Resume |
| `/schedule pause-all` | operator | Pause everything |
| `/schedule resume-all` | operator | Resume everything |

## Scan profiles

Profiles are **fixed argument sets** (`core/profiles.py`). Users pick by
name and can never contribute arguments, which keeps the CLI surface
injection-proof.

| Profile | Flags | Meaning |
| --- | --- | --- |
| `quick` | `-F -T4` | Top 100 ports |
| `service` | `-F -T4 -sV --version-intensity 2` | Top 100 + versions (default) |
| `deep` | `-T4 -sV --top-ports 1000` | Top 1000 ports + versions |

---

## Scheduled monitoring

Off by default. Set `SCHEDULE_ENABLED=true` to activate.

```bash
/schedule add home service 6      # every 6 hours
/schedule list                    # → next run time
/schedule pause home              # config kept, job unregistered
```

Design points worth knowing:

- **One worker.** Manual and scheduled scans share `ScanWorker`, so
  `MAX_CONCURRENT_SCANS` is a real ceiling rather than a per-path wish.
- **One delivery path.** Scheduler jobs submit a job and return; the worker's
  completion callback sends the alert. Nothing bypasses the queue.
- **Failures are contained.** A raising APScheduler job would be dropped with
  no traceback, so job bodies catch and log everything.
- **Alerts need a destination.** A scheduled run has no originating chat, so
  the operator's chat is recorded from the first `/start` (`operator_chats`).
- **Quiet when unchanged.** An unchanged network reports "no changes" rather
  than silence — silence would look like a dead bot, and noise would train the
  operator to ignore alerts.

---

## Retention policy

Runs daily via the scheduler, or on demand with `/cleanup`.

A scan is deleted only when it is **outside the age window** *and* **not
protected**. Protected means:

- among the newest `RETENTION_MAX_SCANS_PER_TARGET` scans, or
- the newest **successful** scan for that target.

The baseline rule is the important one: losing the newest successful scan
would make the next run report every host as brand new. It is always kept,
however old.

"Newest" is ordered by `started_at`, not `id`, so backfilled scans cannot
displace a real baseline.

Deletion happens in FK order — services → hosts → change_events → scans.

---

## Export and reporting

```bash
/export home          # JSON (default)
/export home csv      # one row per service, plus one row per change event
/report home          # last 7 days, human-readable
```

JSON is a full structured dump (scans → hosts → services → change events).
CSV uses a single header with a `record_type` column distinguishing
`service` / `host` / `scan` / `change` rows, so the file stays one
spreadsheet-friendly table.

---

## Change detection

| Type | Meaning |
| --- | --- |
| `new_host` | address absent from the baseline |
| `closed_host` | present before, gone now |
| `new_port` | new open port on a host seen in both scans |
| `closed_port` | open port no longer present |
| `service_change` | same port, different name/product/version |

Service identity is a case- and whitespace-insensitive fingerprint.

**Noise control:** ports on a *newly discovered* host are not reported as
`new_port`. A brand-new host obviously has all its ports new; emitting a line
per port would bury the signal.

---

## Admin panel

A separate FastAPI service on `127.0.0.1:8080` shares the database and the
SQLAlchemy models with the bot. The API is JSON under `/api/*`; the UI is a
React single-page app served from `/admin`.

```
  browser ──▶ admin (FastAPI, :8080)
                ├─ /api/*        JSON, JWT in an HttpOnly cookie
                ├─ /admin/assets hashed JS/CSS   (StaticFiles)
                └─ /admin/*      index.html       (SPA catch-all)
                                   │
                                   └─ React Router owns the rest
```

`admin_users` is a separate table from `telegram_users`: merging them would
let one compromise grant both surfaces. Every action, including those taken
through Telegram, is written to `audit_log`.

### Frontend

The panel lives in `admin/frontend/` — Vite, React 18, TypeScript (`strict`,
no `any`), Tailwind, Radix primitives, TanStack Query, Zustand, Recharts and
sonner. **Node is only needed to build it.** The Docker build compiles the
bundle once and the runtime image has no Node in it, so the bot and the admin
service need nothing installed on the host.

```bash
# one-shot build (what the image does)
cd admin/frontend
npm ci
npm run build        # runs tsc, so a type error fails the build

# live dev server on :5173, proxying /api to the running panel on :8080
npm run dev
```

`npm run typecheck` typechecks without emitting.

Layout:

| Path | Purpose |
| --- | --- |
| `src/lib/api.ts` | typed fetch wrapper, cookie auth, 401 → `/admin/login` |
| `src/store/ui.ts` | theme and sidebar state (Zustand, persisted) |
| `src/components/` | `AppShell`, `DataTable`, `Dialog`, `Badge`, `Switch`, … |
| `src/pages/` | login, dashboard, users, targets, audit, settings |

Colours are CSS variables switched by `data-theme` on `<html>`, so the theme
toggle is one attribute flip rather than a re-render. Dark is the default;
`prefers-color-scheme` is honoured on a first visit, and an inline script in
`index.html` applies the theme before React mounts to avoid a flash.

`admin/frontend/dist/` and `node_modules/` are gitignored — the image builds
its own bundle, and `package-lock.json` is committed so `npm ci` is
reproducible.

---

## Rules

Policy rules let an operator change scan scope, deny-lists, rate limits and
quotas **without editing `.env` and restarting the bot**. Each rule is a row
in `rules`, evaluated by the bot before every scan and manageable from the
panel.

### Rule types

| Type | `value` | Effect |
| --- | --- | --- |
| `allow_cidr` / `deny_cidr` | `192.168.174.0/24,10.0.0.0/8` | Address and CIDR targets |
| `allow_domain` / `deny_domain` | `*.example.com,corp.test` | Hostname targets |
| `allow_port` / `deny_port` | `22,80,8000-9000` | Ports (ranges inclusive) |
| `max_scan_time` | `120` | Seconds; **lowers** the ceiling only |
| `rate_limit` | `60` | Seconds between scans |
| `time_window` | `08:00-22:00`, `22:00-06:00` | UTC window; inside = allowed |
| `user_quota` | `50/day`, `10/hour` | Scans per user per period |

`*.example.com` matches any subdomain but not the bare domain — the behaviour
a DNS wildcard record actually has. Trailing dots are stripped, and input is
forgiving: `8:00 - 9:30` is stored as `08:00-09:30`.

### Evaluation order

Rules sort by `(priority, id)` ascending; `id` breaks ties so the order is
total. Then:

1. **Every** rule is examined. The first one that *denies* short-circuits, so a
   deny at priority 100 still blocks a request that an allow at priority 1
   already matched.
2. **Allow gates fail closed, per family.** Addresses are judged by CIDR rules
   and hostnames by domain rules. If a family has allow rules and none
   matched, the request is denied with `no matching allow rule`. If a family
   has no allow rules, it imposes nothing. Two families do not compensate for
   each other — a matched `allow_domain` does not excuse an unmatched
   `allow_cidr`.
3. `time_window` is a **permission**: inside the window passes, outside is
   denied. Overnight windows such as `22:00-06:00` wrap midnight.
4. `user_quota` is always per user. `rate_limit` is per target by default,
   keyed on the target *name* so it shadows the existing `RateLimiter`;
   `scope="user"` makes it per user. Both must pass.
5. `max_scan_time` resolves to `min(SCAN_TIMEOUT_SECONDS, smallest matching
   rule)`, so a rule can only tighten the ceiling and can never leave a scan
   unbounded. `rate_limit` instead takes the smallest matching rule and falls
   back to the environment value, so a rule *may* relax it.

A decision reports the rule that decided it (`rule_id`, `rule_name`), plus
`effective_rate_limit_seconds` and `effective_scan_timeout`, both of which
flow into the scan that follows.

### Scope

`scope` is `global`, `user` or `target`. A `user` rule with `scope_id` set to
a Telegram ID applies only to that user — and never to a scheduled run, which
has no actor.

### Broken rules

An unknown `rule_type` or a malformed `value` is logged and **skipped**, so a
typo cannot deny legitimate traffic. The one exception: an unreadable `scope`
on a *deny* rule is treated as `global`, because a restriction should not
stand down over a typo.

### Known limitation: no DNS resolution

A hostname is judged by its own domain rules. A hostname that resolves to a
denied address is **not** caught, because the engine performs no DNS lookup.
Resolution would make the decision depend on the network and on timing, and a
policy check that can be steered by DNS is worse than one that is honest about
its blind spot.

### Port rules and the shipped profiles

Port rules apply only when the engine is told which ports a scan will probe.
`ScanProfile.port_list()` supplies them, and **the three shipped profiles
return `()`** — they use nmap's `-F` and `--top-ports`, which resolve to
nmap's own port tables at run time. Hardcoding a copy of those tables would go
stale the next time nmap updates, so the honest answer is that the port list is
unknown, and port rules cannot be evaluated for `quick`, `service` or `deep`.
A profile declaring an explicit `-p` list enables them.

### API

All under `/api/rules`, role-gated and audited.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/rules` | `?type=&enabled=&scope=&q=`; ordered by priority |
| `POST` | `/api/rules` | 400 bad value, 409 duplicate name |
| `PATCH` | `/api/rules/{id}` | Partial; re-validates the resulting row |
| `DELETE` | `/api/rules/{id}?confirm=true` | 400 without `confirm` |
| `POST` | `/api/rules/{id}/toggle` | Flips `enabled` |
| `POST` | `/api/rules/reorder` | `{ids:[3,1,2]}` → priorities 1..3 |
| `POST` | `/api/rules/test` | **Dry run.** No hit row, no counter change |
| `GET` | `/api/rules/{id}/hits` | Paginated history for one rule |
| `GET` | `/api/rules/export` | JSON download; hits excluded |
| `POST` | `/api/rules/import` | Superadmin; all-or-nothing, upserts by name |
| `GET` | `/api/rule-hits` | All rules, filterable |

`POST /api/rules/test` is the one to reach for first. It returns exactly what
the engine would decide, with no side effects:

```bash
curl -b cookie -H 'Content-Type: application/json' \
  -d '{"target":"10.0.0.5"}' http://127.0.0.1:8080/api/rules/test
```

```json
{
  "allowed": false,
  "reason": "blocked by deny_cidr rule: 10.0.0.5 is in 10.0.0.0/8",
  "rule_id": 2,
  "rule_name": "deny-ten",
  "effective_rate_limit_seconds": null,
  "effective_scan_timeout": null,
  "warnings": [],
  "rules_considered": 3,
  "rules_enabled": 1,
  "side_effects": "none"
}
```

`import` validates every rule before writing anything, so one bad entry
rejects the batch instead of leaving a half-applied configuration behind.

### Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `rules_enabled` | `true` | Master switch; `false` skips evaluation entirely |
| `rules_default_action` | `allow` | Reserved for a future gate; informational |
| `rules_max_hits_per_day` | `10000` | Stop recording hits past this, keep evaluating |

Past the hit cap, evaluation continues — losing history is survivable, losing
enforcement is not. The cap is logged once a day, not once per scan.

### History and retention

`rule_hits` records an evaluation only when a rule *decided* the outcome, so
it answers "what did this rule set actually do?" rather than logging every
scan. `hit_count` and `last_hit_at` on the rule move in the same transaction
as the row, so the counter cannot disagree with the history it links to.

Retention prunes `rule_hits` older than `RETENTION_DAYS` and reports
`rule_hits_deleted`. **Rules are never deleted by retention** — a rule
outliving its own history would leave the surviving rows unexplainable.

---

## Setup

```bash
cp .env.example .env
chmod 600 .env
# set TELEGRAM_BOT_TOKEN and ALLOWED_USER_IDS

docker compose up -d --build
```

The build runs `npm ci && npm run build` for the admin panel, so the
first build downloads the Node toolchain and every dependency. No Node
is required on the host.

To restrict scanning, set `ALLOWED_CIDRS` (e.g. `192.168.174.0/24`). When set,
targets outside those ranges are rejected and hostnames are refused — they
cannot be proven in-scope without resolution, so the check fails closed.

---

## Security

- **Fail closed.** Empty `ALLOWED_USER_IDS` refuses to start. Empty
  `ALLOWED_CIDRS` means *no restriction*, which is the opposite default —
  set it for real deployments.
- **Strict target parsing.** IP, CIDR, or hostname only. Targets starting
  with `-` are rejected; shell metacharacters are rejected.
- **No shell.** `subprocess` is always called with an argument list.
- **No user-supplied nmap flags.** Only fixed profiles.
- **Token never logged.** httpx echoes full request URLs, which embed the
  bot token in the path. `main.py` silences `httpx`, `telegram`,
  `telegram.ext`, `apscheduler` and `asyncio` loggers.
- **`.env` can never enter an image.** `.dockerignore` ignores `.env*`
  (whitelisting `.env.example`) and the Dockerfile copies packages explicitly
  rather than `COPY . .`.
- **Silent-handler guard.** Every command replies on every exit path, and a
  catch-all error handler turns any unhandled exception into a user-visible
  message plus a logged traceback.

---

## Configuration

All config flows through `config/settings.py`; no other module reads
`os.environ`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | — | **required** |
| `ALLOWED_USER_IDS` | — | **required**, comma-separated |
| `ALLOWED_CIDRS` | *(empty)* | Restricts scan targets |
| `DATABASE_URL` | compose default | PostgreSQL DSN |
| `NMAP_BINARY` | `nmap` | Scanner path |
| `SCAN_TIMEOUT_SECONDS` | `60` | Per-scan timeout |
| `MAX_CONCURRENT_SCANS` | `2` | Worker slots |
| `DEFAULT_PROFILE` | `service` | Used when none given |
| `RATE_LIMIT_SECONDS` | `30` | Min gap per target |
| `SCHEDULE_ENABLED` | `false` | Master switch |
| `SCHEDULE_INTERVAL_HOURS` | `6` | Default interval |
| `SCHEDULE_PROFILE` | `service` | Default scheduled profile |
| `RETENTION_DAYS` | `30` | Age limit |
| `RETENTION_MAX_SCANS_PER_TARGET` | `100` | Count cap |
| `EXPORT_MAX_SCANS` | `20` | Scans per export |

---

## Tests

```bash
# tests are excluded from the image, so bind-mount the tree and run as your uid
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
  --entrypoint bash nmap-bot-bot \
  -lc 'pip install -q --user pytest pytest-asyncio && PATH="$HOME/.local/bin:$PATH" python -m pytest -q'
```

758 tests, no network access required — `tests/test_v1_integration.py` drives
the full pipeline and the scheduler with a stub runner.

Layout:

| File | Covers |
| --- | --- |
| `test_change_detector.py` | diff logic, noise control |
| `test_parser.py` | nmap XML parsing, normalization |
| `test_pipeline.py` | scan manager end-to-end |
| `test_security.py` | authN/authZ, target validation |
| `test_targets.py` | target parsing, scope |
| `test_deletion.py` | block-by-default delete, purge |
| `test_handlers.py` | detached-instance safety |
| `test_v1_units.py` | rate limiter, exporters, reporter, logging |
| `test_retention.py` | selection logic, FK order, baseline safety |
| `test_v1_integration.py` | scheduler lifecycle, shared worker, change→alert |
| `test_admin_api.py` | admin API, role gating, SPA shell serving |
| `test_admin_auth.py` | password hashing, JWT, login throttling |
| `test_admin_users_stats.py` | user CRUD, dashboard queries |
| `test_audit_settings.py` | audit trail, settings coercion |
| `test_i18n.py` | translation coverage and fallback |
| `test_rules_model.py` | `rules` table shape, defaults, constraints |
| `test_rule_values.py` | rule value parsers and matchers |
| `test_rule_engine.py` | evaluation order, gates, scoping, limits |
| `test_rule_repository.py` | rule CRUD, ordering, hits, retention |
| `test_admin_rules_api.py` | rules API, role gating, import atomicity |
| `test_scan_rules_integration.py` | rules in the live `/scan` path |

The frontend has its own gate: `npm run build` runs `tsc`, so a type
error fails the admin image build.

---

## Known limitations

- **Port rules cannot fire for the shipped profiles.** They delegate port
  selection to nmap (`-F`, `--top-ports`), so the engine is never told the
  port list and `allow_port`/`deny_port` are inert. Only a profile declaring
  an explicit `-p` list enables them.
- **The engine resolves no DNS.** A hostname pointing at a denied address
  is not caught; see the Rules section.

- **The SPA is served uncompressed.** Neither uvicorn nor Starlette's
  `StaticFiles` applies gzip or brotli, so a browser pulls ~1 MB of
  assets (~290 KB gzipped) on a cold cache. Put a reverse proxy that
  compresses in front for anything beyond localhost.
- **The panel has no TLS and no CSRF token.** It binds to
  `127.0.0.1` and sets `ADMIN_COOKIE_SECURE=false`; both need revisiting
  behind a proxy (`csrf_required` is reported by the API for this).

- **No auth on read commands.** `/targets`, `/scans`, `/export`, `/report`
  and `/health` are available to any allowed user, not just operators.
  `/export` in particular can dump scan history.
- **Retention is per-target and unindexed.** `deletable_ids` loads all scan
  rows for a target each pass; fine at this scale, linear at large scale.
- **Scan history grows linearly.** `hosts`/`services` are stored per scan, so
  a scan-every-6-hours target accumulates 4 rows/day/host. Retention bounds
  it, but there is no aggregation.
- **`/cleanup` is not transactional across targets.** Each target commits
  independently, so a mid-run failure leaves earlier deletions applied.
- **Hostname targets under `ALLOWED_CIDRS` are always refused.** Correct but
  surprising; a DNS-resolution step would be needed to allow them.
- **Operator chat is never forgotten.** Alerts go to whoever ran `/start`
  first; there is no `/setalertchat`.
- **Not exercised through Telegram end-to-end.** The V1 handlers were
  verified by unit and integration tests plus direct calls, not by sending
  real chat messages.
- **Postgres credentials in `docker-compose.yml` are development defaults.**