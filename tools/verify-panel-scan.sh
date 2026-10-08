#!/bin/bash
# Verify panel-originated scanning against the live service.
#
# Copies the probe in inside check(): the admin container is recreated by the
# gate between phases, and a fresh container has a fresh filesystem.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

docker compose cp "$DIR/verify-panel-scan.py" admin:/tmp/vps.py >/dev/null 2>&1
docker compose exec -T -w /app -e PYTHONPATH=/app admin python /tmp/vps.py 2>&1 \
  | grep -vE 'InsecureKeyLength|self\._jws|error reading bcrypt|most recent call|File "/usr/local|version = _bcrypt|AttributeError: module|StarletteDeprecation|from starlette'
exit "${PIPESTATUS[0]}"