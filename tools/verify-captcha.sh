#!/bin/bash
# Run the live CAPTCHA check against the running admin service.
#
# The setting is read by Settings.from_env() at process start, so it cannot be
# changed with `docker compose exec -e` for an already-running admin. This
# sets it in .env, recreates admin, runs the check, and restores the original
# value -- so the deployment is left exactly as it was found.
#
#   ./tools/verify-captcha.sh
#
# Prints no credentials. Exit code is non-zero if any check fails.
set -uo pipefail

cd "$(dirname "$0")/.."



original="$(grep -o '^CAPTCHA_ENABLED=.*' .env || echo 'CAPTCHA_ENABLED=false')"
echo "original: $original"
fail=0

restore() {
    echo
    echo "restoring $original"
    if grep -q '^CAPTCHA_ENABLED=' .env; then
        sed -i "s/^CAPTCHA_ENABLED=.*/$original/" .env
    else
        printf '\n%s\n' "$original" >> .env
    fi
    docker compose up -d --force-recreate admin >/dev/null 2>&1
    sleep 30
    docker compose ps --format 'table {{.Service}}\t{{.Status}}'
}
trap restore EXIT

for value in false true; do
    echo
    echo "##############################################################"
    echo "# CAPTCHA_ENABLED=$value"
    echo "##############################################################"

    if grep -q '^CAPTCHA_ENABLED=' .env; then
        sed -i "s/^CAPTCHA_ENABLED=.*/CAPTCHA_ENABLED=$value/" .env
    else
        printf '\nCAPTCHA_ENABLED=%s\n' "$value" >> .env
    fi

    docker compose up -d --force-recreate admin >/dev/null 2>&1
    sleep 30

    status="$(docker compose ps admin --format '{{.Status}}')"
    echo "admin: $status"
    case "$status" in
        *healthy*) ;;
        *) echo "  [FAIL] admin not healthy: $status"; fail=1; continue ;;
    esac

    # Copied per branch, not once up front: the container is recreated between
    # branches and a fresh container has a fresh filesystem.
    docker compose cp tools/verify-captcha.py admin:/tmp/vc.py >/dev/null 2>&1
    docker compose exec -T -w /app -e PYTHONPATH=/app \
        admin python /tmp/vc.py 2>&1 \
      | grep -vE 'InsecureKeyLength|self\._jws|error reading bcrypt|most recent call|File "/usr/local|version = _bcrypt|AttributeError: module|StarletteDeprecation|from starlette'
    rc="${PIPESTATUS[0]}"
    [ "$rc" -eq 0 ] || fail=1
done

echo
[ $fail -eq 0 ] && echo "CAPTCHA VERIFY: both branches passed" \
                 || echo "CAPTCHA VERIFY: FAILURES PRESENT"
exit $fail