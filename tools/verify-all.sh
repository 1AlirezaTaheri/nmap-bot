#!/bin/bash
# Phase 1: build, deploy, then verify -- refusing to verify a stale image.
#
# The previous run built, the build FAILED on a tsc error, and the verify
# script then reported against the previously deployed bundle anyway. Its
# output looked plausible and its failures were about the old code, which is
# worse than no output. So the build's exit status is checked here, before the
# verifier is allowed to run at all.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

echo "=== typecheck ==="
# The exit status of the typecheck is captured before any pipe is attached.
# `... | tail -4` inside a subshell, followed by reading PIPESTATUS, yields
# tail's status, so a genuine type error passed the gate and the build ran
# anyway -- which is how a failed build once got verified against a stale
# bundle.
tsc_out="$(cd admin/frontend && bash "$DIR/tsc.sh" 2>&1)"
tsc_rc=$?
echo "$tsc_out" | tail -4
if [ "$tsc_rc" != "0" ]; then
    echo "TYPECHECK FAILED (exit $tsc_rc) -- not deploying, not verifying"
    exit 1
fi

echo
echo "=== build ==="
docker compose build admin 2>&1 | tail -3
if [ "${PIPESTATUS[0]}" != "0" ]; then
    echo "BUILD FAILED -- not deploying, not verifying"
    exit 1
fi

echo
echo "=== deploy ==="
docker compose up -d 2>&1 | tail -3
sleep 40
docker compose ps --format 'table {{.Service}}\t{{.Status}}'

echo
echo "=== verify the deployed bundle ==="
bash "$DIR/verify-ui.sh" 2>&1 | tail -30

echo
echo "=== verify the live dashboard ==="
bash "$DIR/verify-dashboard.sh" 2>&1 | tail -40

echo
echo "=== verify the target detail API ==="
bash "$DIR/verify-target-detail-api.sh" 2>&1 | tail -45

echo
echo "=== verify the target detail UI in the bundle ==="
bash "$DIR/verify-target-detail.sh" 2>&1 | tail -30

echo
echo "=== verify panel scanning ==="
bash "$DIR/verify-panel-scan.sh" 2>&1 | tail -40

echo
echo "=== verify mobile navigation ==="
bash "$DIR/verify-mobile-nav.sh" 2>&1 | tail -25

echo
fail=0
echo "done"
