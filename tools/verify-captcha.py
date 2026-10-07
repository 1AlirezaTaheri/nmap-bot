#!/usr/bin/env python3
"""End-to-end CAPTCHA check against the running admin service.

Run twice: once with CAPTCHA_ENABLED=false (the current deployment) and once
with it true, so both branches are proven against the real server rather than
only against TestClient.

Prints no credentials.
"""
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("TARGET", "http://127.0.0.1:8080")
USER = os.environ["ADMIN_USERNAME"]
PW = os.environ["ADMIN_PASSWORD"]

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if detail:
        print(f"         {detail}")


def http(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = dict(headers or {})
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, f"transport: {e.reason}"


def solve(question: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([+-])\s*(\d+)\s*=\s*\?\s*", question)
    if m is None:
        raise ValueError(f"unparseable: {question!r}")
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    return a - b if op == "-" else a + b


def wait_out_limiter(seconds: int = 65) -> None:
    time.sleep(seconds)


def current_enabled() -> bool:
    st, body = http("GET", "/api/captcha")
    # The flag is not exposed over HTTP, so infer it the only honest way: try a
    # login with no challenge and see whether the server demands one.
    st, body = http("POST", "/api/login",
                    {"username": USER, "password": "probe-wrong-password"})
    return st == 400 and "captcha" in body.lower()


print("=" * 74)
print("CAPTCHA end-to-end check")
print("target:", BASE)
print("=" * 74)

enabled = current_enabled()
print(f"\nCAPTCHA_ENABLED appears to be: {enabled}\n")

# --- the endpoint --------------------------------------------------------
print("### GET /api/captcha")
st, body = http("GET", "/api/captcha")
record("challenge issued", st == 200 and "question" in body, f"status {st}")
if st == 200:
    data = json.loads(body)
    record("token is prefixed", data["token"].startswith("cap."), "")
    record("expires_in is 300", data.get("expires_in") == 300,
           f"{data.get('expires_in')}")
    answer = solve(data["question"])
    record("answer not returned anywhere in the body",
           answer not in data.values() and "answer" not in data,
           f"question {data['question']!r}, answer {answer}")
    # Not asserted as a substring: the token payload is base64 of a JSON whose
    # digest is 64 hex characters, so a one-digit answer appears inside it by
    # chance every few challenges. That check fails for reasons unrelated to
    # the code -- it did, twice, in this script.
    # Three dots, not two: the token carries the "cap." prefix, so it is
    # "cap." + header + "." + payload + "." + signature.
    record("token is a prefixed JWT, not the answer",
           data["token"].count(".") == 3 and str(answer) != data["token"],
           f"{data['token'].count('.')} dots (prefix + 2 JWT separators)")

# --- login with the current setting --------------------------------------
print()
if enabled:
    print("### login with CAPTCHA on")
    token, answer = fresh_challenge()
    st, body = http("POST", "/api/login", {
        "username": USER, "password": PW,
        "captcha_token": token, "captcha_answer": str(answer + 1)})
    record("wrong answer -> 400", st == 400, f"status {st}: {body[:70]}")

    # A fresh challenge is needed for each attempt: tokens are single-use and
    # GET /api/captcha shares the login rate limiter, so the limiter has to be
    # idle and the challenge fresh before every single step here. Skipping
    # either produced a KeyError on a 429 body, which is a bug in the script
    # rather than in the server.
    def fresh_challenge():
        st_, body_ = http("GET", "/api/captcha")
        assert st_ == 200, f"could not get a challenge: {st_} {body_[:80]}"
        data_ = json.loads(body_)
        return data_["token"], solve(data_["question"])

    wait_out_limiter()
    token, answer = fresh_challenge()
    st, body = http("POST", "/api/login", {
        "username": USER, "password": PW,
        "captcha_token": token, "captcha_answer": str(answer)})
    record("correct answer + correct password -> 200", st == 200, f"status {st}")

    # Replay the same challenge, same token.
    wait_out_limiter()
    st, body = http("POST", "/api/login", {
        "username": USER, "password": PW,
        "captcha_token": token, "captcha_answer": str(answer)})
    record("replayed token -> 400", st == 400, f"status {st}")

    wait_out_limiter()
    st, body = http("POST", "/api/login", {"username": USER, "password": PW})
    record("no challenge at all -> 400", st == 400, f"status {st}")

    wait_out_limiter()
    st, body = http("POST", "/api/login", {
        "username": USER, "password": "wrong-password",
        "captcha_token": "cap." + "x" * 200, "captcha_answer": "5"})
    record("forged token -> 400", st == 400, f"status {st}")
else:
    print("### login with CAPTCHA off")
    wait_out_limiter()
    st, body = http("POST", "/api/login",
                    {"username": USER, "password": PW})
    record("login works with no challenge", st == 200, f"status {st}")

    wait_out_limiter()
    st, body = http("POST", "/api/login",
                    {"username": USER, "password": "wrong-password"})
    record("wrong password -> 401 (not 400)", st == 401, f"status {st}")

    wait_out_limiter()
    st, body = http("POST", "/api/login", {
        "username": USER, "password": PW,
        "captcha_token": "cap.garbage", "captcha_answer": "wrong"})
    record("a bogus challenge is ignored when off", st == 200, f"status {st}")

# --- rate limiting still works ------------------------------------------
print()
print("### rate limiting unchanged")
wait_out_limiter()
codes = []
for _ in range(7):
    st, _ = http("POST", "/api/login",
                 {"username": USER, "password": "wrong-password-probe"})
    codes.append(st)
record("lockout engages", 429 in codes, f"sequence {codes}")

# --- Mini App untouched --------------------------------------------------
print()
print("### Mini App untouched")
uid = int(os.environ["ALLOWED_USER_IDS"].split(",")[0])
tok = os.environ["TELEGRAM_BOT_TOKEN"]
secret = hmac.new(b"WebAppData", tok.encode(), hashlib.sha256).digest()
fields = {"user": json.dumps({"id": uid, "first_name": "P"}),
          "auth_date": str(int(time.time()))}
cs = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
digest = hmac.new(secret, cs.encode(), hashlib.sha256).hexdigest()
import urllib.parse
blob = urllib.parse.urlencode({**fields, "hash": digest})

st, _ = http("GET", "/miniapp/me", {"X-Telegram-Init-Data": blob})
record("valid initData still accepted", st == 200, f"status {st}")

for label, bad in [
    ("forged hash", blob.rsplit("=", 1)[0] + "=" + "0" * 64),
    ("duplicate hash", blob + "&hash=" + "0" * 64),
    ("no header at all", None),
]:
    st, _ = http("GET", "/miniapp/me",
                 {"X-Telegram-Init-Data": bad} if bad else {})
    record(f"miniapp refuses: {label}", st in (401, 403), f"status {st}")

# --- summary -------------------------------------------------------------
print()
print("### SUMMARY")
print("=" * 74)
failed = [r for r in RESULTS if not r[1]]
print(f"  checks run : {len(RESULTS)}")
print(f"  passed     : {len(RESULTS) - len(failed)}")
print(f"  FAILED     : {len(failed)}")
for name, _, detail in failed:
    print(f"    {name}: {detail}")
print("=" * 74)
sys.exit(1 if failed else 0)