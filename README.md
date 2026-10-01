# NetSentinel

**Network Intelligence & Security Monitoring Assistant** — know what is on
your network, what changed, and what deserves your attention.

A Telegram bot that runs nmap, stores normalized results, and reports
*differences* between scans rather than raw dumps.

## MVP Demo Flow

```
/addtarget lab 192.168.1.0/24     → ✅ Target 'lab' added successfully.
/scan lab                         → 🔍 Scan Started ... Status: Running…
                                  → ✅ Scan Completed  Hosts discovered: 3
                                     Open services: 5  Scan ID: 2
                                  → 🚨 NETWORK CHANGES DETECTED
                                     New host: 192.168.1.37
                                     New port: 192.168.1.10:8080
                                     Service changed: 192.168.1.10:80 (Apache → nginx)
                                     Closed port: 192.168.1.21:23
                                     Summary: +1 host, +2 port, +1 service change, −1 port
```

## Commands

| Command | Purpose |
| --- | --- |
| `/addtarget <name> <value> [group]` | Register a target |
| `/targets` | List targets |
| `/deltarget <name>` | Remove a target |
| `/scan <target\|name> [profile]` | Queue a scan |
| `/scans <name>` | Scan history |
| `/status` | Active/queued scans |
| `/help` | Command reference |

## Scan profiles

Profiles are **fixed argument sets** (`core/profiles.py`). Users pick by
name and can never contribute arguments, which keeps the CLI surface
injection-proof.

| Profile | Flags | Meaning |
| --- | --- | --- |
| `quick` | `-F -T4` | Top 100 ports |
| `service` | `-F -T4 -sV --version-intensity 2` | Top 100 + versions (default) |
| `deep` | `-T4 -sV --top-ports 1000` | Top 1000 ports + versions |

## Architecture

```
User → Telegram Bot
       ├─ security/    authentication → authorization → target scope
       ├─ core/        scan manager, target registry, change detector
       ├─ workers/     queue + bounded concurrency
       ├─ parser/      nmap -oX → xml_parser → normalizer
       ├─ database/    models + repository (PostgreSQL)
       └─ bot/         handlers + message formatting
```

### Pipeline

1. **Authenticate** — the caller's Telegram ID must be in `ALLOWED_USER_IDS`.
2. **Authorize** — role check, then target scope check.
3. **Queue** — the job goes onto an `asyncio.Queue`; the handler returns
   immediately, so the bot stays responsive.
4. **Execute** — a worker thread runs nmap with XML output.
5. **Parse & normalize** — only `open` ports are kept, addresses lowercased,
   ports sorted, strings whitespace-normalized.
6. **Persist** — scan, hosts, services written in one transaction.
7. **Detect** — diff against the last successful scan of the same
   target+profile.
8. **Alert** — completion message plus a change report to the chat.

### Change detection

`core/change_detector.py` is a pure module — no database, no Telegram, no
I/O — so it is directly unit-testable. It reports:

| Type | Meaning |
| --- | --- |
| `new_host` | address absent from the baseline |
| `closed_host` | present before, gone now |
| `new_port` | new open port on a host seen in both scans |
| `closed_port` | open port no longer present |
| `service_change` | same port, different name/product/version |

Service identity is a case- and whitespace-insensitive fingerprint, so
`HTTP`/`nginx`/`1.0` and `http`/`nginx`/` 1.0 ` are the same service.

**Noise control:** ports on a *newly discovered* host are not reported as
`new_port`. A brand-new host obviously has all its ports new; emitting a
line per port would bury the signal.

## Setup

```bash
cp .env.example .env
chmod 600 .env
# set TELEGRAM_BOT_TOKEN and ALLOWED_USER_IDS (your numeric user ID)

docker compose up -d --build
```

To opt into a restricted scan range, set `ALLOWED_CIDRS` (e.g.
`192.168.0.0/16`). When set, targets outside those ranges are rejected.
Hostname targets are refused in that mode — they cannot be proven in-scope
without resolution, so the check fails closed.

## Security

- **Fail closed.** An empty `ALLOWED_USER_IDS` refuses to start, rather
  than defaulting to "allow everyone".
- **Strict target parsing.** IP, CIDR, or hostname only. Targets starting
  with `-` are rejected (an option, not a target); shell metacharacters
  (`;`, `&`, `|`, `$`, backticks, …) are rejected.
- **No shell.** `subprocess` is always called with an argument list.
- **No user-supplied nmap flags.** Only fixed profiles.
- **`.env` can never enter an image.** `.dockerignore` plus explicit
  per-package `COPY` lines in the Dockerfile.
- **Minimal token scope.** With `ALLOWED_CIDRS` unset, any valid target is
  allowed, so restrict it for a real deployment.

## Tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

62 tests, no network access required — `tests/test_pipeline.py` drives the
full pipeline with a stub runner.

## Known issues

- httpx request logging can leak the bot token into logs.
- No user allow-list UI (env-var only for now).
- No per-target scan scheduling yet (roadmap item: scheduled monitoring).
- PostgreSQL credentials in `docker-compose.yml` are development defaults;
  change them for any real deployment.