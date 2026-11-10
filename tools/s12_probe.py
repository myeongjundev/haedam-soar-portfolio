"""S12 baseline probe: GET a URL at a fixed interval and log latency (KST) to CSV.

Each request opens a new connection. With --source the socket is bound to that
local address so the portal sees it as the client IP (e.g. Kali 203.0.113.100).
Every request is written, including timeouts and connection errors.
Standard library only (Python 3.8+).
"""
import argparse
import csv
import errno
import http.client
import ipaddress
import math
import hashlib
import json
from pathlib import Path
import socket
import statistics
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://192.0.2.2:5000/api/v1/health")
ap.add_argument("--source", default=None, help="local IPv4 address to send from, written in full (e.g. 203.0.113.100)")
ap.add_argument("--interval", type=float, default=2.0)
ap.add_argument("--duration", type=float, default=1800.0, help="seconds")
ap.add_argument("--timeout", type=float, default=3.0)
ap.add_argument("--label", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()


def positive(name, v):
    # finite and > 0; rejects 0, negatives, NaN and inf so the pacing stays real
    if not math.isfinite(v) or v <= 0:
        raise SystemExit(f"--{name} must be a finite number > 0 (got {v})")
    return v


positive("interval", a.interval)
positive("duration", a.duration)
positive("timeout", a.timeout)
if a.source is not None:
    ipaddress.IPv4Address(a.source)   # reject partial forms like ".100"
u = urllib.parse.urlsplit(a.url)
if u.scheme != "http":
    raise SystemExit("only http:// URLs are supported")
host, port = u.hostname, u.port or 80
path = (u.path or "/") + (f"?{u.query}" if u.query else "")


def probe():
    """Return (status, ms, error, local_ip). status 0 means no HTTP response."""
    conn = http.client.HTTPConnection(host, port, timeout=a.timeout,
                                      source_address=(a.source, 0) if a.source else None)
    t0 = time.perf_counter()
    local = ""
    try:
        conn.connect()
        local = conn.sock.getsockname()[0]
        conn.request("GET", path, headers={"Connection": "close"})
        r = conn.getresponse()
        r.read()
        return r.status, (time.perf_counter() - t0) * 1000, "", local
    except (socket.timeout, TimeoutError):
        return 0, (time.perf_counter() - t0) * 1000, "timeout", local
    except OSError as e:   # e.g. EADDRNOTAVAIL when --source is not on this host
        name = type(e).__name__ if type(e) is not OSError else errno.errorcode.get(e.errno, "OSError")
        return 0, (time.perf_counter() - t0) * 1000, name, local
    except http.client.HTTPException as e:
        return 0, (time.perf_counter() - t0) * 1000, type(e).__name__, local
    finally:
        conn.close()


rows = []
started_at = datetime.now(KST).isoformat(timespec="milliseconds")
metadata_path = Path(a.out + '.meta.json')
if metadata_path.exists():
    raise SystemExit('metadata already exists; use a new run-id path')
end = time.monotonic() + a.duration
nxt = time.monotonic()
# 'x' refuses an existing file so a re-run with the same --out keeps the earlier run's evidence
try:
    out_file = open(a.out, "x", newline="", encoding="utf-8")
except FileExistsError:
    raise SystemExit(f"--out already exists: {a.out} (use a new run-id path to keep the earlier evidence)")
with out_file as f:
    w = csv.writer(f)
    w.writerow(["ts_kst", "label", "source", "status", "ms", "error"])
    while time.monotonic() < end:
        ts = datetime.now(KST).isoformat(timespec="milliseconds")
        status, ms, err, local = probe()
        if a.source and local and local != a.source:
            err = (err + ";" if err else "") + f"source_mismatch:{local}"
        w.writerow([ts, a.label, local or (a.source or ""), status, round(ms, 1), err])
        f.flush()
        rows.append((status, ms))
        nxt += a.interval
        time.sleep(max(0, nxt - time.monotonic()))

safe_url = urllib.parse.urlunsplit((u.scheme, f'{host}:{port}', u.path or '/', '', ''))
metadata = {
    'schema_version': '1.0', 'url': safe_url,
    'url_redacted': bool(u.username or u.password or u.query or u.fragment),
    'label': a.label, 'requested_source': a.source,
    'interval_seconds': a.interval, 'timeout_seconds': a.timeout,
    'duration_seconds': a.duration, 'started_at': started_at,
    'finished_at': datetime.now(KST).isoformat(timespec="milliseconds"),
    'sample_count': len(rows), 'csv_sha256': hashlib.sha256(Path(a.out).read_bytes()).hexdigest(),
}
with metadata_path.open('x', encoding='utf-8') as metadata_file:
    json.dump(metadata, metadata_file, ensure_ascii=False, indent=2, allow_nan=False)
    metadata_file.write('\n')

ok = sorted(ms for s, ms in rows if 200 <= s < 400)


def pct(p):
    return ok[min(len(ok) - 1, int(len(ok) * p))] if ok else float("nan")


print(f"{a.label}: n={len(rows)} ok={len(ok)} fail={len(rows) - len(ok)} "
      f"median={statistics.median(ok) if ok else float('nan'):.1f}ms p95={pct(.95):.1f}ms "
      f"p99={pct(.99):.1f}ms max={max(ok) if ok else float('nan'):.1f}ms")
