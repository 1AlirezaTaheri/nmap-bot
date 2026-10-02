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

## Setup

```bash
cp .env.example .env
chmod 600 .env
# set TELEGRAM_BOT_TOKEN and ALLOWED_USER_IDS

docker compose up -d --build
```

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

139 tests, no network access required — `tests/test_v1_integration.py` drives
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

---

## Known limitations

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