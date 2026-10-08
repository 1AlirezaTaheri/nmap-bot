#!/bin/bash
# Verify the deployed dashboard: the API endpoints, and that the new UI code is
# actually in the served bundle.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

echo "### dashboard endpoints (live)"
docker compose cp "$DIR/verify-dashboard-api.py" admin:/tmp/vda.py >/dev/null 2>&1
docker compose exec -T -w /app -e PYTHONPATH=/app admin python /tmp/vda.py 2>&1 \
  | grep -vE 'InsecureKeyLength|self\._jws|error reading bcrypt|most recent call|File "/usr/local|version = _bcrypt|AttributeError: module|StarletteDeprecation|from starlette'
api_rc="${PIPESTATUS[0]}"

echo
echo "### dashboard UI in the served bundle"
base="https://127.0.0.1:8443"
# Concatenate EVERY emitted chunk, not just the entry. Vite code-splits
# recharts into its own ~410 kB chunk, so grepping only index-*.js reported it
# absent while the dashboard was rendering AreaChart and BarChart perfectly.
chunks=$(curl -sk "$base/admin" | grep -o '/admin/assets/[^"]*\.js')
js=""
for c in $chunks; do
    js="$js$(curl -sk "$base$c")"
done
echo "  (searched $(echo "$chunks" | wc -w) chunk(s))"
for c in $chunks; do echo "    $c"; done

# Authored strings, so a minified bundle is still greppable.
for probe in \
    'Scan activity' \
    'Change types' \
    'Most-changed targets' \
    'Unavailable' \
    'updated ' \
    'queued' ; do
    if grep -q "$probe" <<<"$js"; then
        echo "  [PASS] '$probe' present"
    else
        echo "  [FAIL] '$probe' absent"
        api_rc=1
    fi
done

# Recharts chart types must be in the bundle.
for chart in 'recharts' 'AreaChart' 'BarChart'; do
    if grep -qi "$chart" <<<"$js"; then
        echo "  [PASS] $chart present"
    else
        echo "  [FAIL] $chart absent"
        api_rc=1
    fi
done

echo
echo "### the SPA still serves"
for p in /admin /admin/targets /admin/audit /admin/settings /admin/style-guide; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$base$p")
    if [ "$code" = "200" ]; then echo "  [PASS] $p"; else echo "  [FAIL] $p -> $code"; api_rc=1; fi
done

echo
[ "$api_rc" -eq 0 ] && echo "DASHBOARD VERIFY: all passed" \
                    || echo "DASHBOARD VERIFY: FAILURES PRESENT"
exit "$api_rc"