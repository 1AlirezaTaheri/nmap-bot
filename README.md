# Telegram Nmap Scanner Bot

Automated network scanning via Telegram chat. Send `/scan <target>` and get nmap
results back as text or as a file.

## Architecture

| Layer | Component |
| --- | --- |
| **User** | Telegram App — `/start`, `/scan` |
| **Network** | Telegram API (`api.telegram.org`) → V2Ray proxy (VLESS, SOCKS5 `:10808`) |
| **Host** | Ubuntu 25.10 @ `192.168.174.128`, SSH `:22`, Docker 29.7.2 |
| **Container** | image `nmap-bot`, base `python:3.11-slim`, `ENV TELEGRAM_BOT_TOKEN` |
| **Application** | Python 3.11, `python-telegram-bot` 21.6, handlers `/start` + `/scan` |
| **Scanner** | nmap 7.95 — `nmap -F -T4 <target>` (fast scan, top 100 ports) |
| **Target** | e.g. `8.8.8.8`, `scanme.nmap.org` |

## Data flow

```
forward:  User → Telegram API → V2Ray → Ubuntu → Docker → Bot → nmap → Target
return:   User ← Telegram API ← V2Ray ← Ubuntu ← Docker ← Bot ← nmap ← Target
```

## Project files

| File | Purpose |
| --- | --- |
| `bot.py` | Bot entrypoint — `/start` and `/scan` handlers |
| `requirements.txt` | `python-telegram-bot==21.6` |
| `Dockerfile` | `python:3.11-slim` + nmap |
| `.env` | `TELEGRAM_BOT_TOKEN` — gitignored, `chmod 600` |
| `.env.example` | Template for `.env` |
| `make_graphical_abstract.py` | Generates `graphical_abstract.png` (Graphviz) |
| `graphical_abstract.png` | Architecture diagram |

## Setup

```bash
cp .env.example .env
chmod 600 .env
# put your real bot token in .env

docker build -t nmap-bot .
docker run -d --env-file .env --name my-nmap-bot nmap-bot
```

## Security notes

- Bot token lives in the container environment, never in source control.
- `.env` is gitignored and must stay `chmod 600`.
- Known issues to address: httpx log leak, no user allow-list, no target
  restrictions.
