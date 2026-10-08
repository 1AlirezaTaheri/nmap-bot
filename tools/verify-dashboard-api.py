#!/usr/bin/env python3
"""Prove the three new endpoints answer correctly against the live service.

Runs inside the admin process so it uses the same settings, database and auth
path the panel uses. Prints no credentials.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

BASE = "http://127.0.0.1:8080"
USER = os.environ["ADMIN_USERNAME"]
PW = os.environ["ADMIN_PASSWORD"]

fails = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        fails.append(name)


def call(path, opener=None, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with (opener.open if opener else urllib.request.urlopen)(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except urllib.error.URLError as e:
        return 0, {"error": str(e.reason)}


jar = CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

print("### auth required")
for path in ["/api/stats/top-targets", "/api/stats/worker", "/api/stats/schedule"]:
    st, _ = call(path)
    check(f"{path} refuses unauthenticated", st == 401, f"status {st}")

# Login, respecting the rate limiter: wait out the window if needed.
for attempt in range(3):
    req = urllib.request.Request(
        BASE + "/api/login",
        data=json.dumps({"username": USER, "password": PW}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with op.open(req, timeout=20) as r:
            if r.status == 200:
                break
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    if code == 429:
        print("  (rate limited, waiting out the 60s window)")
        time.sleep(65)
    else:
        break
else:
    print("  could not sign in")
    sys.exit(1)

print()
print("### /api/stats/top-targets")
st, body = call("/api/stats/top-targets", op)
check("200", st == 200, f"status {st}")
check("has targets[] and days",
      isinstance(body.get("targets"), list) and body.get("days") == 7,
      f"days={body.get('days')}, {len(body.get('targets', []))} row(s)")
if body.get("targets"):
    row = body["targets"][0]
    check("row shape", set(row) == {"id", "name", "value", "changes",
                                    "last_change_at"}, str(sorted(row)))
    counts = [t["changes"] for t in body["targets"]]
    check("sorted worst-first", counts == sorted(counts, reverse=True), str(counts))

st, body = call("/api/stats/top-targets?days=100000", op)
check("days clamped to 90", body.get("days") == 90, f"days={body.get('days')}")
st, body = call("/api/stats/top-targets?days=0", op)
check("days floored to 1", body.get("days") == 1, f"days={body.get('days')}")

print()
print("### /api/stats/worker")
st, body = call("/api/stats/worker", op)
check("200", st == 200, f"status {st}")
check("full shape",
      set(body) == {"available", "running", "queue_depth", "active",
                    "pending", "max_concurrency"},
      str(sorted(body)))
# The admin process DOES prepare a scan worker for the Mini App
# (bootstrap._prepare_miniapp_worker), so `available: true` is the expected
# state here and the counters are real. An earlier version of this check
# asserted available: false, derived from a probe that constructed the app
# without ever running its lifespan -- so no worker was ever started and the
# assertion passed for the wrong reason.
#
# What must hold either way is the invariant: present means integers, absent
# means nulls. Zeros for an absent worker would read as "idle" and be wrong.
if body.get("available"):
    ok = all(
        isinstance(body.get(k), int) and not isinstance(body.get(k), bool)
        for k in ("queue_depth", "active", "pending")
    )
    check("present worker reports integers", ok,
          f"queue={body.get('queue_depth')} active={body.get('active')} "
          f"pending={body.get('pending')} slots={body.get('max_concurrency')}")
else:
    ok = all(body.get(k) is None for k in ("queue_depth", "active", "pending"))
    check("absent worker reports nulls, not zeros", ok,
          f"available={body.get('available')}")

print()
print("### /api/stats/schedule")
st, body = call("/api/stats/schedule", op)
check("200", st == 200, f"status {st}")
check("reports the switch", isinstance(body.get("enabled"), bool),
      f"enabled={body.get('enabled')}")
check("does not invent a next_run",
      body.get("next_run_at") is None and body.get("next_run_known") is False,
      f"known={body.get('next_run_known')}")

print()
print("### /api/stats is unchanged")
st, body = call("/api/stats", op)
check("200", st == 200, f"status {st}")
expected = {
    "targets", "scans", "scans_24h", "scans_24h_failed", "changes",
    "changes_24h", "telegram_users", "admins", "hosts", "services",
    "last_scan_at", "series", "change_breakdown", "recent_audit",
    "operator_chat",
}
missing = expected - set(body)
check("all original keys present", not missing, f"missing {missing}" if missing else
      f"{len(expected)} keys")
check("no keys added", not (set(body) - expected),
      str(set(body) - expected) if set(body) - expected else "")
check("series has the chart shape",
      isinstance(body.get("series"), list)
      and all({"date", "scans", "failed", "changes"} <= set(p)
              for p in body["series"]),
      f"{len(body.get('series', []))} day(s)")

print()
print("=" * 60)
if fails:
    print(f"DASHBOARD API: {len(fails)} FAILED: {fails}")
    sys.exit(1)
print("DASHBOARD API: all passed")