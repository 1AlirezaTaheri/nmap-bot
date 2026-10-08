#!/bin/bash
# Typecheck, then reinstall deps only if the check found no node_modules.
#
# The earlier failure was an artefact of this script, not of the code: I had
# deleted node_modules to clean up after the vite build, so `npx tsc` fell back
# to downloading a different package literally named `tsc` from the registry
# ("This is not the tsc command you are looking for"). The Dockerfile build is
# unaffected; it installs its own.
set -uo pipefail
cd /home/alireza/nmap-bot/admin/frontend

if [ ! -d node_modules ]; then
    echo "=== installing dev deps for the typecheck ==="
    docker run --rm -v "$PWD:/app" -w /app -u "$(id -u):$(id -g)" \
        --entrypoint sh node:20-alpine -c 'npm install --no-audit --no-fund' 2>&1 | tail -5
fi

echo
echo "=== typecheck ==="
docker run --rm -v "$PWD:/app" -w /app \
    --entrypoint sh node:20-alpine -c \
    './node_modules/.bin/tsc --noEmit -p tsconfig.json' 2>&1 | head -40
echo "EXIT=${PIPESTATUS[0]}"