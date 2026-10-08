#!/bin/bash
# Verify the target-detail page is present in the deployed SPA.
#
# The bundle is minified, so this greps for authored strings and for the route
# paths rather than for symbols. Every emitted chunk is searched, because Vite
# code-splits.
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
echo "### detail-page strings"
# Probes are single JSX text fragments, never a phrase that spans an
# interpolation. `Activity — last {days} days` compiles to two separate string
# literals, so grepping for the joined phrase cannot match no matter how the
# code is written -- the first version of this check did exactly that and
# reported two false failures.
for probe in \
    'All targets' \
    'Full detail' \
    'Activity â€” last' \
    'Activity' \
    'Port distribution' \
    'Hosts and services' \
    'No schedule for this target' \
    'Copied' \
    'Delete permanently' \
    'most recent of' ; do
    if grep -q "$probe" <<<"$js"; then
        echo "  [PASS] '$probe'"
    else
        echo "  [FAIL] '$probe' absent"
        fail=1
    fi
done

echo
echo "### the detail route is registered"
# /targets/:id appears as a compiled path pattern in the route table.
if grep -q 'targets/:id\|targets/:' <<<"$js"; then
    echo "  [PASS] /targets/:id present"
else
    echo "  [FAIL] /targets/:id absent"
    fail=1
fi

echo
echo "### the detail page fetches the new endpoints"
for ep in '/timeline' '/hosts'; do
    if grep -q "$ep" <<<"$js"; then
        echo "  [PASS] $ep referenced"
    else
        echo "  [FAIL] $ep absent"
        fail=1
    fi
done

echo
echo "### the SPA serves the detail path"
# Client-side routing means this returns index.html rather than 404, which is
# the correct behaviour for a deep link.
for p in /admin/targets /admin/targets/3 /admin/targets/999999; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$base$p")
    if [ "$code" = "200" ]; then
        echo "  [PASS] $p"
    else
        echo "  [FAIL] $p -> $code"
        fail=1
    fi
done

echo
echo "### pre-existing pages still serve"
for p in /admin /admin/audit /admin/settings /admin/telegram-users /admin/style-guide; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$base$p")
    if [ "$code" = "200" ]; then echo "  [PASS] $p"; else echo "  [FAIL] $p -> $code"; fail=1; fi
done

echo
[ $fail -eq 0 ] && echo "TARGET DETAIL UI: all passed" \
                 || echo "TARGET DETAIL UI: FAILURES PRESENT"
exit $fail