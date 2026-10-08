"""Exercise the three target-detail routes against the live service.

Signs in, picks a real target from /api/targets, and walks the detail flow.
Prints no credentials.
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


jar = CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(path, opener=None):
    req = urllib.request.Request(BASE + path)
    try:
        with (opener.open if opener else urllib.request.urlopen)(req, timeout=25) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except urllib.error.URLError as e:
        return 0, {"error": str(e.reason)}


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
        print("  (rate limited, waiting out the window)")
        time.sleep(65)
    else:
        break
else:
    print("could not sign in")
    sys.exit(1)

print("### auth required")
for path in ["/api/targets/1", "/api/targets/1/timeline",
             "/api/targets/1/scans/1/hosts"]:
    st, _ = call(path)
    check(f"{path} refuses unauthenticated", st == 401, f"status {st}")

print()
print("### pick a real target")
st, listing = call("/api/targets", op)
check("/api/targets 200", st == 200, f"status {st}")
targets = listing.get("targets", [])
check("at least one target exists", len(targets) > 0, f"{len(targets)} target(s)")
if not targets:
    print("no targets to exercise; stopping")
    sys.exit(1)

# Prefer a target that actually has scans. Taking targets[0] picked a freshly
# added target with zero scans, so the hosts endpoint -- the whole reason for
# this run -- was skipped and the check passed without ever being exercised.
picked = None
for candidate in targets:
    st_probe, body_probe = call(f"/api/targets/{candidate['id']}/scans", op)
    if st_probe == 200 and body_probe.get("scans"):
        picked = candidate
        break

if picked is None:
    picked = max(
        targets,
        key=lambda t: t.get("scan_count", 0) if isinstance(t.get("scan_count"), int) else 0,
    )
    print("  note: no target reported any scans; using the busiest anyway")

target = picked
tid = target["id"]
print(f"  using target {tid}: {target['name']} ({target['value']})")

print()
print("### GET /api/targets/{id}")
st, body = call(f"/api/targets/{tid}", op)
check("200", st == 200, f"status {st}")
check("full shape",
      set(body) == {"id", "name", "value", "group", "enabled",
                    "created_at", "scan_count", "schedule"},
      str(sorted(body)))
check("matches the list entry",
      body.get("name") == target["name"] and body.get("value") == target["value"])
check("scan_count is an int", isinstance(body.get("scan_count"), int),
      f"scan_count={body.get('scan_count')}")

st, _ = call("/api/targets/999999", op)
check("unknown target -> 404", st == 404, f"status {st}")

print()
print("### GET /api/targets/{id}/timeline")
st, body = call(f"/api/targets/{tid}/timeline", op)
check("200", st == 200, f"status {st}")
series = body.get("series", [])
check("series present", isinstance(series, list), f"{len(series)} day(s)")
check("default window is 30 days", body.get("days") == 30, f"days={body.get('days')}")
check("every bucket has the chart shape",
      all({"date", "scans", "failed", "changes"} <= set(p) for p in series),
      "ok" if series else "empty")
check("no future buckets",
      all(p["date"] <= time.strftime("%Y-%m-%d") for p in series))
check("dates are ascending",
      [p["date"] for p in series] == sorted(p["date"] for p in series))

st, body = call(f"/api/targets/{tid}/timeline?days=100000", op)
check("days clamped to 365", body.get("days") == 365, f"days={body.get('days')}")
st, body = call(f"/api/targets/{tid}/timeline?days=0", op)
check("days floored to 1", body.get("days") == 1, f"days={body.get('days')}")
st, _ = call("/api/targets/999999/timeline", op)
check("unknown target -> 404", st == 404, f"status {st}")

print()
print("### GET /api/targets/{id}/scans  (pre-existing, reused)")
st, body = call(f"/api/targets/{tid}/scans", op)
check("200", st == 200, f"status {st}")
scans = body.get("scans", [])
check("returns a list", isinstance(scans, list), f"{len(scans)} scan(s)")
if scans:
    scan = scans[0]
    check("scan row shape",
          {"id", "profile", "status", "source", "started_at",
           "duration_ms", "host_count", "service_count"} <= set(scan),
          str(sorted(scan)))

print()
print("### GET /api/targets/{id}/scans/{scan_id}/hosts")
if not scans:
    print("  (no scans for this target, skipping)")
else:
    sid = scans[0]["id"]
    st, body = call(f"/api/targets/{tid}/scans/{sid}/hosts", op)
    check("200", st == 200, f"status {st}")
    check("has scan, hosts and port_distribution",
          set(body) == {"scan", "hosts", "port_distribution"}, str(sorted(body)))
    hosts = body.get("hosts", [])
    print(f"  {len(hosts)} host(s), "
          f"{len(body.get('port_distribution', []))} distinct port(s)")
    if hosts:
        h = hosts[0]
        check("host row shape",
              {"id", "address", "hostname", "state", "services"} <= set(h),
              str(sorted(h)))
        check("services sorted by port",
              all(
                  [s["port"] for s in h["services"]]
                  == sorted(s["port"] for s in h["services"])
                  for h in hosts
              ))
    dist = body.get("port_distribution", [])
    check("port counts descending",
          all(dist[i]["count"] >= dist[i + 1]["count"]
              for i in range(len(dist) - 1)),
          str([d["count"] for d in dist]))

    # IDOR: a scan id that is valid but belongs to another target must 404.
    other = next((t for t in targets if t["id"] != tid), None)
    if other:
        st, _ = call(f"/api/targets/{other['id']}/scans/{sid}/hosts", op)
        check("scan from another target -> 404 (IDOR)", st == 404, f"status {st}")

    st, _ = call(f"/api/targets/{tid}/scans/999999/hosts", op)
    check("unknown scan -> 404", st == 404, f"status {st}")

print()
print("### pre-existing target routes are unchanged")
st, body = call(f"/api/targets/{tid}/changes", op)
check("/changes still works", st == 200, f"status {st}")

print()
print("=" * 60)
if fails:
    print(f"TARGET DETAIL API: {len(fails)} FAILED: {fails}")
    sys.exit(1)
print("TARGET DETAIL API: all passed")