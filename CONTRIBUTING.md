# Contributing to NetSentinel

## Running the tests

The suite needs no network access and no running database — everything runs
against a temporary SQLite file per test.

Inside the container (recommended, so versions match production):

```bash
cd ~/nmap-bot
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
  --entrypoint bash nmap-bot-bot \
  -lc 'pip install -q --user pytest pytest-asyncio && PATH="$HOME/.local/bin:$PATH" python -m pytest -q'
```

Expect `139 passed`.

Two details matter here. `--user` is required because the image runs as
uid 10001 while the project files belong to your uid. And the bind mount is
needed because `.dockerignore` excludes `tests/` from the image — so
`docker compose run` will report "no tests ran".

Run a subset or a single test by name:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
  --entrypoint bash nmap-bot-bot \
  -lc 'pip install -q --user pytest pytest-asyncio && PATH="$HOME/.local/bin:$PATH" python -m pytest tests/test_change_detector.py -v'

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
  --entrypoint bash nmap-bot-bot \
  -lc 'pip install -q --user pytest pytest-asyncio && PATH="$HOME/.local/bin:$PATH" python -m pytest -k retention -v'
```

Locally, if you have Python 3.11:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

## Layout

```
config/     settings — the only module that reads os.environ
security/   authentication, authorization, target scope
bot/        composition root + command handlers + message formatting
core/       scan manager, target registry, change detector, scheduler,
            retention, exporters, reporter, rate limiter, logging
parser/     nmap runner, XML parser, normalizer
database/   models, engine, repositories
workers/    shared background scan worker
tests/      one file per concern
```

## Rules worth keeping

**The change detector stays pure.** `core/change_detector.py` must not import
the database, Telegram, or do I/O. That purity is what makes the core product
logic directly unit-testable — it is the reason diffing is trusted.

**SQL stays in the repository layer.** Handlers and services call repository
methods; they never build queries. If you find yourself writing `select(` in a
handler, it belongs in `database/repository.py`.

**Every command replies on every exit path.** A handler that can exit
silently is indistinguishable from a dead bot. This is not theoretical — a
`/deltarget` failure went unnoticed for hours because of it. If you add a
command, handle the error branches and add them to the test suite.

**Config flows through `config/settings.py`.** No other module reads
`os.environ`. New settings get a default and an `.env.example` entry.

**Never log the token.** httpx logs full request URLs, and the token is in the
path. Keep the logger silencers in `main.py` intact.

**Profiles are fixed argument sets.** Users select a profile by name; they
never supply nmap arguments. Keep it that way — it is what makes the CLI
surface injection-proof.

## Adding a command

1. Add the handler in `bot/handlers/` — one module per command group.
2. Put the wording in `bot/messages/reports.py`, not in the handler, so it
   stays testable without a Telegram connection.
3. Register it in `bot/app.py`.
4. Add tests: happy path, and every error branch.

## Adding a setting

1. Add the field to `Settings` in `config/settings.py` with a default.
2. Document it in `.env.example` and the README configuration table.
3. Add a test for parsing and for the fail-closed behaviour if it is
   required.

## Before you commit

```bash
pytest -q                     # all green
git status                     # no .env, no *.bak, no logs
```

If `.env` or a backup file appears in `git status`, stop and fix
`.gitignore` before committing. `.gitignore` ignores `.env*` and whitelists
`.env.example`; a token-bearing `.env.bak-*` slipping through once is how
credentials get published.

## Deployment

```bash
cd ~/nmap-bot
docker compose up -d --build
docker compose logs --tail=50 bot
```

The Dockerfile uses `tini` as PID 1 so SIGTERM reaches Python and the
scheduler can stop cleanly. `restart: unless-stopped` on both services.

After changing `settings.py`, add any new variables to `.env` yourself — the
image will not do it for you, and the bot fails closed on missing required
values.

---

## The rule engine stays pure

`core/rules.py` decides whether a request may proceed. It must keep doing only
that. Concretely:

- **No database access.** Quota counts and last-scan times arrive through
  `RuleContext`; the repository supplies them. If the engine grows a query, the
  tests stop being able to run without a fixture and the hot path grows I/O.
- **No DNS.** A hostname is judged by its domain rules, and one resolving to a
  denied address is not caught. Resolution would make the decision depend on
  the network and on timing.
- **No Telegram, no clock.** `RuleContext.now` is injectable; a time-dependent
  rule is tested by passing a time, not by freezing anything.
- **Total parsers.** A `validate_value` in `core/rule_values.py` returns a
  normalized string or raises `ValueError`. Never return something the engine
  would later have to re-validate.

When adding a rule type, touch all of: the `RULE_TYPES` vocabulary, a parser,
a matcher in `rule_values.py`, a branch in the engine, and the docs. There is a
test asserting `KNOWN_TYPES` matches `RULE_TYPES`, so a type added without a
parser fails loudly.

### Where the boundary is

| Concern | Owner |
| --- | --- |
| Whether a request is permitted | `core/rules.py` |
| Reading a rule value, matching it | `core/rule_values.py` |
| Counting scans, loading rules, recording hits | `database/repository.py` |
| Deciding when to consult the engine | `bot/handlers/scan.py` |
| Exposing and editing rules | `admin/routes/rules.py` |
