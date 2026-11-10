"""S12 request-flood tool: send GET requests at staged rates and log every result.

Purpose: drive a controlled HTTP request flood from an attack source address so
the S12 "service outage / availability" case can be exercised (before-measurement
and after). It is the attack counterpart of tools/s12_probe.py (steady 1 req / 2 s).

Safety and scope:
- GET only. The default target is /api/v1/health so each request makes one portal
  event (web.request) and one DB read, matching the 2026-10-23 VPN baseline path.
  (GET /login makes two events per request: web.request + web.file_access.)
- Rates and runtime are capped (see --max-rate, --concurrency, --duration).
- Stops on Ctrl+C, on --duration, on a stop file, or when the 403 ratio in a
  sampling window crosses --stop-on-block (the source got blocked).
- Binds each request to --source so the portal sees that attack IP. Partial forms
  like ".41" are rejected. Writes every request (including timeouts/errors) to CSV.
- Standard library only (Python 3.8+). No write requests, no auth, no credentials.

This tool generates real load against a real target: confirm the target, source,
rate and window with the team before running, and keep the normal-source baseline
and portal-origin-vs-D-arrival counts for the same window.
"""
import argparse
import csv
import errno
import http.client
import ipaddress
import math
import os
import signal
import socket
import statistics
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

ap = argparse.ArgumentParser(description="S12 staged request flood (GET only).")
ap.add_argument("--url", default="http://192.0.2.2:5000/api/v1/health",
                help="target URL (GET). default /api/v1/health = 1 event/req")
ap.add_argument("--source", default=None, help="attack source IPv4, written in full (e.g. 203.0.113.41)")
ap.add_argument("--rates", default="5,10,20,40,80", help="per-second rates per stage, comma separated")
ap.add_argument("--stage-seconds", type=float, default=60.0, help="seconds per stage")
ap.add_argument("--max-rate", type=float, default=100.0, help="hard cap on any stage rate (req/s)")
ap.add_argument("--concurrency", type=int, default=10, help="worker threads (cap 50)")
ap.add_argument("--duration", type=float, default=300.0, help="overall seconds, hard cap 600")
ap.add_argument("--timeout", type=float, default=5.0, help="per-request timeout (s)")
ap.add_argument("--stop-on-block", type=float, default=0.5,
                help="stop when 403 ratio in the last window reaches this (0 disables)")
ap.add_argument("--stop-file", default=None, help="stop when this file appears")
ap.add_argument("--label", required=True)
ap.add_argument("--out", required=True, help="per-request CSV path")
a = ap.parse_args()

# Fixed safety ceiling: no run may exceed this request rate, whatever --max-rate says.
RATE_CEILING = 100.0


def positive(name, v):
    if not math.isfinite(v) or v <= 0:
        raise SystemExit(f"--{name} must be a finite number > 0 (got {v})")
    return v


positive("stage-seconds", a.stage_seconds)
positive("duration", a.duration)
positive("timeout", a.timeout)
positive("max-rate", a.max_rate)
if a.max_rate > RATE_CEILING:
    raise SystemExit(f"--max-rate must be <= {RATE_CEILING:g} req/s (got {a.max_rate})")
if not (0.0 <= a.stop_on_block <= 1.0) or not math.isfinite(a.stop_on_block):
    raise SystemExit("--stop-on-block must be between 0 and 1")

cap = min(a.max_rate, RATE_CEILING)
try:
    raw_rates = [float(x) for x in a.rates.split(",") if x.strip()]
except ValueError:
    raise SystemExit("--rates must be comma-separated numbers")
if not raw_rates:
    raise SystemExit("no rates given")
for r in raw_rates:
    positive("rates", r)
rates = [min(r, cap) for r in raw_rates]   # each stage clamped to the ceiling

if a.source is not None:
    ipaddress.IPv4Address(a.source)   # reject partial forms like ".41"
u = urllib.parse.urlsplit(a.url)
if u.scheme != "http":
    raise SystemExit("only http:// URLs are supported")
if (u.path or "/").rstrip("/") in ("/login", "/api/v1/auth/login"):
    print("NOTE: /login makes 2 events per request (web.request + web.file_access).")
host, port = u.hostname, u.port or 80
path = (u.path or "/") + (f"?{u.query}" if u.query else "")

concurrency = max(1, min(a.concurrency, 50))
duration = min(a.duration, 600.0)

stop = threading.Event()
lock = threading.Lock()
rows = []            # (status, ms) for summary
window = []          # recent statuses for the block check


def now_kst():
    return datetime.now(KST).isoformat(timespec="milliseconds")


def one_request():
    conn = http.client.HTTPConnection(host, port, timeout=a.timeout,
                                      source_address=(a.source, 0) if a.source else None)
    t0 = time.perf_counter()
    local, status, err = "", 0, ""
    try:
        conn.connect()
        local = conn.sock.getsockname()[0]
        conn.request("GET", path, headers={"Connection": "close"})
        r = conn.getresponse()
        r.read()
        status = r.status
    except (socket.timeout, TimeoutError):
        err = "timeout"
    except OSError as e:   # e.g. EADDRNOTAVAIL when --source is not on this host
        err = type(e).__name__ if type(e) is not OSError else errno.errorcode.get(e.errno, "OSError")
    except http.client.HTTPException as e:
        err = type(e).__name__
    finally:
        conn.close()
    ms = (time.perf_counter() - t0) * 1000
    if a.source and local and local != a.source:
        err = (err + ";" if err else "") + f"source_mismatch:{local}"
    return local or (a.source or ""), status, round(ms, 1), err


def stop_tripped():
    # one place to decide "no new request should start"
    if stop.is_set():
        return True
    if time.monotonic() >= overall_end:
        return True
    if a.stop_file and os.path.exists(a.stop_file):
        return True
    return False


def pace_until(t):
    # Wait for the next dispatch slot in short slices so Ctrl-C, --stop-file, the
    # deadline and the 403 stop are noticed within ~0.2s even at very low rates.
    while not stop_tripped():
        left = t - time.monotonic()
        if left <= 0:
            return
        stop.wait(min(left, 0.2))


writer_lock = threading.Lock()
# 'x' refuses an existing file so a re-run with the same --out keeps the earlier run's evidence
try:
    csv_file = open(a.out, "x", newline="", encoding="utf-8")
except FileExistsError:
    raise SystemExit(f"--out already exists: {a.out} (use a new run-id path to keep the earlier evidence)")
writer = csv.writer(csv_file)
writer.writerow(["ts_start_kst", "ts_finish_kst", "label", "stage_rate", "source", "status", "ms", "error"])

signal.signal(signal.SIGINT, lambda *_: stop.set())
print(f"{a.label}: target {a.url} source {a.source or '(host default)'} "
      f"rates {rates} x {a.stage_seconds}s, conc {concurrency}, cap {duration}s")

sem = threading.Semaphore(concurrency)
inflight = []


def dispatch_one(stage_rate):
    # Capture the stage rate and start time now, at dispatch, not at response time,
    # so a slow request is not misfiled into the next stage.
    def task():
        try:
            ts_start = now_kst()
            local, status, ms, err = one_request()
            ts_finish = now_kst()
            with writer_lock:
                writer.writerow([ts_start, ts_finish, a.label, stage_rate, local, status, ms, err])
                csv_file.flush()
            with lock:
                rows.append((status, ms))
                window.append(status)
                if len(window) > 400:
                    del window[:len(window) - 400]
        finally:
            sem.release()
    sem.acquire()
    # Re-check AFTER waiting on the semaphore: the deadline/stop-file may have passed while queued.
    if stop_tripped():
        sem.release()
        return
    t = threading.Thread(target=task, daemon=True)
    with lock:
        inflight.append(t)
    t.start()


start = time.monotonic()
overall_end = start + duration
try:
    for rate in rates:
        if stop_tripped():
            break
        stage_end = min(time.monotonic() + a.stage_seconds, overall_end)
        interval = 1.0 / rate
        nxt = time.monotonic()
        while time.monotonic() < stage_end:
            if stop_tripped():   # check BEFORE dispatching, so no request goes out past the line
                break
            dispatch_one(rate)
            nxt += interval
            pace_until(min(nxt, stage_end))
            with lock:
                recent = window[-20:]
            if a.stop_on_block and len(recent) >= 20:
                ratio = sum(1 for s in recent if s == 403) / 20.0
                if ratio >= a.stop_on_block:
                    print(f"stop: 403 ratio {ratio:.0%} in last 20")
                    stop.set()
        if stop_tripped():
            break
finally:
    stop.set()
    # Drain in-flight requests and record how long that took, separately from the run.
    drain0 = time.monotonic()
    for _ in range(concurrency):
        sem.acquire()
    drain_s = time.monotonic() - drain0
    csv_file.close()

ok = sorted(ms for s, ms in rows if 200 <= s < 400)
blocked = sum(1 for s, _ in rows if s == 403)
failed = sum(1 for s, _ in rows if s == 0)


def pct(p):
    return ok[min(len(ok) - 1, int(len(ok) * p))] if ok else float("nan")


print(f"{a.label}: sent {len(rows)} ok {len(ok)} blocked403 {blocked} failed {failed} "
      f"median {statistics.median(ok) if ok else float('nan'):.1f}ms "
      f"p95 {pct(.95):.1f}ms max {max(ok) if ok else float('nan'):.1f}ms "
      f"elapsed {drain0 - start:.1f}s drain {drain_s:.1f}s")
