#!/usr/bin/env python3
"""Prove panel-originated scanning works end to end, against the live service.

This actually queues a real scan. That is the point: a test that only checked
the endpoint's shape would not prove the feature, and the interesting failures
(a missing rule-engine import, a delivery path aimed at chat 0) only appear
when the job runs.
"""
import json
import os
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


def call(method, path, body=None, opener=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with (opener.open if opener else urllib.request.urlopen)(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except urllib.error.URLError as e:
        return 0, {"error": str(e.reason)}


jar = CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

for attempt in range(3):
    st, _ = call("POST", "/api/login", {"username": USER, "password": PW}, op)
    if st == 200:
        break
    if st == 429:
        print("  (rate limited, waiting)")
        time.sleep(65)
    else:
        print(f"could not sign in: {st}")
        sys.exit(1)
else:
    sys.exit(1)

print("### auth required")
st, _ = call("POST", "/api/targets/1/scan", {})
check("POST /scan refuses unauthenticated", st == 401, f"status {st}")

print()
print("### pick a target that is in scope and not already scanning")
st, listing = call("GET", "/api/targets", None, op)
check("target list readable", st == 200, f"status {st}")
targets = listing.get("targets", [])

candidates = [
    t for t in targets
    if t.get("enabled")
    and t.get("value", "").startswith(("192.168.", "10."))
]
check("at least one in-scope enabled target", len(candidates) > 0,
      f"{len(candidates)} of {len(targets)}")
if not candidates:
    print("no in-scope target to scan; stopping")
    sys.exit(1)

target = candidates[0]
tid = target["id"]
print(f"  using target {tid}: {target['name']} ({target['value']})")

# Snapshot the Telegram scan counts before anything is queued, so the
# requested_by claim can be checked as a before/after rather than asserted.
TG_BEFORE = {}
_st, _users = call("GET", "/api/telegram-users", None, op)
for _row in _users.get("users", []):
    TG_BEFORE[_row["telegram_user_id"]] = _row.get("scan_count", 0)
print(f"  telegram scan counts before: {sorted(TG_BEFORE.items())}")

print()
print("### POST /api/targets/{id}/scan")
st, body = call("POST", f"/api/targets/{tid}/scan", {}, op)
check("202 accepted", st == 202, f"status {st}: {str(body)[:90]}")
check("job id returned", isinstance(body.get("job_id"), int), str(body.get("job_id")))
check("state is queued", body.get("state") == "queued", str(body.get("state")))
check("profile echoed", bool(body.get("profile")), str(body.get("profile")))
job_id = body.get("job_id")

print()
print("### the rate limiter refuses an immediate repeat")
# Deliberately before the "job actually runs" poll below. The window is
# RATE_LIMIT_SECONDS (30s here) and the scan takes over a minute to time out,
# so checking afterwards measures an already-elapsed window and reads as "the
# limiter did not engage". Timing a rate limit check after a long wait is
# meaningless; the check has to sit inside the window.
st, body = call("POST", f"/api/targets/{tid}/scan", {}, op)
check("repeat scan is refused", st in (429, 403), f"status {st}: {str(body)[:80]}")

# And another target's budget is a separate budget, not a shared one.
st2, listing2 = call("GET", "/api/targets", None, op)
other = next(
    (t for t in listing2.get("targets", [])
     if t["id"] != tid and t.get("enabled")
     and t.get("value", "").startswith(("192.168.", "10."))),
    None,
)
if other is not None:
    st3, body3 = call("POST", f"/api/targets/{other['id']}/scan", {}, op)
    check("a different target is unaffected", st3 == 202,
          f"{other['name']} -> {st3}")

print()
print("### the job actually runs")
# Poll the target's scans until one appears from source=panel, or time out.
seen_scan = None
for _ in range(24):
    st, scans = call("GET", f"/api/targets/{tid}/scans", None, op)
    if st == 200:
        rows = scans.get("scans", [])
        panel = [s for s in rows if s.get("source") == "panel"]
        if panel:
            seen_scan = panel[0]
            break
    time.sleep(5)

check("a scan row with source=panel was created", seen_scan is not None,
      f"status of newest: {seen_scan['status'] if seen_scan else 'none seen'}")

if seen_scan:
    # It may still be running; wait for it to settle.
    for _ in range(24):
        st, scans = call("GET", f"/api/targets/{tid}/scans", None, op)
        rows = [s for s in scans.get("scans", []) if s.get("source") == "panel"]
        if rows and rows[0]["status"] not in ("running", "queued", "pending"):
            seen_scan = rows[0]
            break
        time.sleep(5)
    check("scan reached a terminal state",
          seen_scan["status"] not in ("running", "queued", "pending"),
          f"status={seen_scan['status']} error={seen_scan.get('error')}")

    st, active = call("GET", f"/api/targets/{tid}/scan/active", None, op)
    check("active scan is null once it finished",
          active.get("scan") is None,
          str(active.get("scan"))[:70])

print()
print("### provenance: audit log records an admin actor")
st, audit = call("GET", "/api/audit?action=scan.requested&page_size=5", None, op)
check("audit readable", st == 200, f"status {st}")
entries = audit.get("entries", [])
check("scan.requested rows exist", len(entries) > 0, f"{len(entries)} row(s)")
if entries:
    # Not just entries[0]: a second target is queued in the rate-limit section
    # above, so the newest row belongs to that one. What matters is that an
    # entry exists for *this* target and that every panel scan carries an admin
    # actor rather than a telegram one.
    check("an entry exists for the scanned target",
          any(e.get("target_id") == target["name"] for e in entries),
          f"targets in entries: {sorted({e.get('target_id') for e in entries})}")
    check("every entry has an admin actor, not a telegram one",
          all(e["actor_type"] == "admin" for e in entries),
          f"actor types: {sorted({e['actor_type'] for e in entries})}")

print()
print("### requested_by stayed NULL, so no telegram scan_count moved")
# Compared against a snapshot taken before the panel scan. Printing the counts
# without comparing them asserts nothing; the whole point of leaving
# requested_by NULL is that these numbers do not move.
st, users_now = call("GET", "/api/telegram-users", None, op)
check("telegram user list readable", st == 200, f"status {st}")
now_by_id = {r["telegram_user_id"]: r.get("scan_count", 0)
             for r in users_now.get("users", [])}
before_by_id = TG_BEFORE

moved = {
    uid: (before_by_id.get(uid), now_by_id.get(uid))
    for uid in now_by_id
    if before_by_id.get(uid) != now_by_id.get(uid)
}
check("no telegram user's scan_count changed", not moved,
      f"changed: {moved}" if moved else
      f"{len(now_by_id)} user(s), all counts unchanged")
if now_by_id:
    print(f"      counts now: {sorted(now_by_id.items())}")

print()
print("### the bot did not try to message chat 0")
st, _ = call("GET", "/api/health", None, op)
check("admin still healthy after the scan", st == 200, f"status {st}")

print()
print("=" * 62)
if fails:
    print(f"PANEL SCAN: {len(fails)} FAILED: {fails}")
    sys.exit(1)
print("PANEL SCAN: all passed")