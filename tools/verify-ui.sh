#!/bin/bash
# Verify the deployed SPA: assets exist, the new code is actually in the
# bundle, and every page still serves.
#
# The bundle is minified, so this greps for stable strings rather than symbols.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1 -> $3"; else echo "  [FAIL] $1 -> $3 (want $2)"; fail=1; fi; }

base="https://127.0.0.1:8443"

echo "### pages served"
for p in /admin /admin/targets /admin/audit /admin/settings /admin/telegram-users /admin/login; do
    chk "GET $p" 200 "$(curl -sk -o /dev/null -w '%{http_code}' "$base$p")"
done

echo
echo "### assets referenced by index.html exist"
asset_js=$(curl -sk "$base/admin" | grep -o '/admin/assets/[^"]*\.js' | head -1)
asset_css=$(curl -sk "$base/admin" | grep -o '/admin/assets/[^"]*\.css' | head -1)
echo "  js:  $asset_js"
echo "  css: $asset_css"
chk "js asset served"  200 "$(curl -sk -o /dev/null -w '%{http_code}' "$base$asset_js")"
chk "css asset served" 200 "$(curl -sk -o /dev/null -w '%{http_code}' "$base$asset_css")"

echo
echo "### new Phase 1 code is in the bundle"
js=$(curl -sk "$base$asset_js")

# Command palette: cmdk ships its own group/empty markup.
grep -q 'cmdk' <<<"$js" && echo "  [PASS] cmdk bundled" || { echo "  [FAIL] cmdk absent"; fail=1; }

# Radix Tabs / Popover render data-state and role attributes.
grep -q 'role="tablist"\|tablist' <<<"$js" && echo "  [PASS] tablist present" || { echo "  [FAIL] tablist absent"; fail=1; }

# Command palette shortcut hint text, authored in this change.
grep -q 'Search pages and targets' <<<"$js" && echo "  [PASS] palette placeholder present" || { echo "  [FAIL] palette placeholder absent"; fail=1; }

grep -q 'Command palette' <<<"$js" && echo "  [PASS] palette aria label present" || { echo "  [FAIL] palette aria label absent"; fail=1; }

# Breadcrumb labels: the fallback literal 'Admin' is gone from the crumbs path.
grep -q 'Telegram Users' <<<"$js" && echo "  [PASS] nav labels present" || { echo "  [FAIL] nav labels absent"; fail=1; }

echo
echo "### new CSS tokens present"
css=$(curl -sk "$base$asset_css")
for token in '--success:' '--shadow-glow' '--ring:' '--shadow-lg'; do
    if grep -q -- "$token" <<<"$css"; then
        echo "  [PASS] $token"
    else
        echo "  [FAIL] $token missing"
        fail=1
    fi
done

# These must actually count toward the exit status. The first version used
# `grep && echo || echo`, which prints FAIL but leaves $fail untouched, so the
# script ended with "all passed" while three checks had visibly failed.
for utility in 'duration-fast' 'duration-normal' 'duration-accordion' 'ease-standard' 'shadow-glow'; do
    if grep -q "\.$utility" <<<"$css"; then
        echo "  [PASS] .$utility emitted"
    else
        echo "  [FAIL] .$utility absent"
        fail=1
    fi
done

echo
echo "### security headers still intact through caddy"
hdrs=$(curl -sk -D - -o /dev/null "$base/admin")
for h in x-content-type-options x-frame-options content-security-policy; do
    grep -qi "^$h:" <<<"$hdrs" && echo "  [PASS] $h" || { echo "  [FAIL] $h missing"; fail=1; }
done

echo
echo "### bundle size (phase 1 delta)"
js_kb=$(( $(wc -c <<<"$js") / 1024 ))
css_kb=$(( $(wc -c <<<"$css") / 1024 ))
echo "  js  ${js_kb} KB uncompressed"
echo "  css ${css_kb} KB uncompressed"

echo
[ $fail -eq 0 ] && echo "PHASE 1 VERIFY: all passed" || echo "PHASE 1 VERIFY: FAILURES PRESENT"
exit $fail