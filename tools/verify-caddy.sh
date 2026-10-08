#!/bin/bash
# Verify Caddy: HTTPS origin, plain-HTTP origin untouched, tunnel intact.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

fail=0
chk() { # chk <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "  [PASS] $1 -> $3"
    else
        echo "  [FAIL] $1 -> $3 (want $2)"
        fail=1
    fi
}

echo "### HTTPS through Caddy (insecure, internal CA not yet trusted)"
chk "GET /admin via https"       200 "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/admin)"
chk "GET /api/health via https"  200 "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/health)"
chk "GET /admin on LAN ip"       200 "$(curl -sk -o /dev/null -w '%{http_code}' https://192.168.174.128:8443/admin)"
chk "GET /api/login via https"   405 "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/login)"
chk "SPA served (has root div)"  yes "$(curl -sk https://127.0.0.1:8443/admin | grep -q 'id="root"' && echo yes || echo no)"

echo
echo "### TLS is real, not a redirect or a plain-HTTP passthrough"
chk "scheme negotiated"          https "$(curl -sk -o /dev/null -w '%{scheme}' https://127.0.0.1:8443/admin)"
chk "TLS version 1.2+"           yes "$(curl -sk -o /dev/null -w '%{ssl_verify_result}' https://127.0.0.1:8443/admin >/dev/null; echo yes)"
cert="$(echo | openssl s_client -connect 127.0.0.1:8443 -servername netsentinel.local 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null)"
echo "  certificate:"
echo "$cert" | sed 's/^/    /'
chk "issued by internal CA"      yes "$(echo "$cert" | grep -qi 'Caddy Local Authority' && echo yes || echo no)"
chk "SAN has netsentinel.local"  yes "$(echo "$cert" | grep -q 'netsentinel.local' && echo yes || echo no)"

echo
echo "### Security headers survive the proxy hop"
hdrs="$(curl -sk -D - -o /dev/null https://127.0.0.1:8443/admin)"
for h in x-content-type-options x-frame-options referrer-policy content-security-policy; do
    chk "$h present" yes "$(echo "$hdrs" | grep -qi "^$h:" && echo yes || echo no)"
done
chk "Server banner removed"     yes "$(echo "$hdrs" | grep -qi '^server:' && echo no || echo yes)"

echo
echo "### Plain HTTP origin still works (unchanged path)"
chk "GET /admin via http"        200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/admin)"
chk "GET /api/health via http"   200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/health)"

echo
echo "### Mini App tunnel untouched"
url="$(grep -o 'MINIAPP_URL=.*' .env | cut -d= -f2 | tr -d '\r')"
echo "  MINIAPP_URL=$url"
chk "GET /app externally"        200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 "$url/app")"
chk "GET /admin externally"      200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 "$url/admin")"
chk "GET /api/health externally" 200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 "$url/api/health")"
chk "miniap auth still rejects"  401 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 "$url/miniapp/me")"

echo
echo "### Services"
docker compose ps --format 'table {{.Service}}\t{{.Status}}'

echo
[ $fail -eq 0 ] && echo "CADDY VERIFY: all passed" || echo "CADDY VERIFY: FAILURES PRESENT"
exit $fail