#!/bin/bash
# Verify mobile navigation and the scan controls in the deployed SPA.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

base="https://127.0.0.1:8443"
fail=0

chunks=$(curl -sk "$base/admin" | grep -o '/admin/assets/[^"]*\.js')
js=""
for c in $chunks; do
    js="$js$(curl -sk "$base$c")"
done
echo "  (searched $(echo "$chunks" | wc -w) chunk(s))"

echo
echo "### mobile navigation"
# The aria labels are the proof that the drawer is announced, which is the part
# a grep can actually speak to. The breakpoint behaviour is not.
for probe in \
    'Open navigation' \
    'Close navigation' \
    'Navigation' \
    'Sign out' ; do
    if grep -q "$probe" <<<"$js"; then
        echo "  [PASS] '$probe'"
    else
        echo "  [FAIL] '$probe' absent"
        fail=1
    fi
done

# aria-modal and aria-haspopup are emitted as literal attribute names by the
# compiler when they are not spread.
grep -q 'aria-modal' <<<"$js" && echo "  [PASS] aria-modal present" \
    || { echo "  [FAIL] aria-modal absent"; fail=1; }
grep -q 'aria-haspopup' <<<"$js" && echo "  [PASS] aria-haspopup present" \
    || { echo "  [FAIL] aria-haspopup absent"; fail=1; }

echo
echo "### scan controls"
for probe in \
    'Scan now' \
    'Scanning' \
    'Queueing' \
    'Scan in progress' ; do
    if grep -q "$probe" <<<"$js"; then
        echo "  [PASS] '$probe'"
    else
        echo "  [FAIL] '$probe' absent"
        fail=1
    fi
done

# The two endpoints the button drives.
for ep in '/scan/active' ; do
    grep -q "$ep" <<<"$js" && echo "  [PASS] $ep referenced" \
        || { echo "  [FAIL] $ep absent"; fail=1; }
done

echo
echo "### every page still serves"
for p in /admin /admin/targets /admin/targets/3 /admin/audit /admin/settings \
         /admin/telegram-users /admin/style-guide; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$base$p")
    if [ "$code" = "200" ]; then
        echo "  [PASS] $p"
    else
        echo "  [FAIL] $p -> $code"
        fail=1
    fi
done

echo
[ $fail -eq 0 ] && echo "MOBILE NAV: all passed" || echo "MOBILE NAV: FAILURES PRESENT"
exit $fail
