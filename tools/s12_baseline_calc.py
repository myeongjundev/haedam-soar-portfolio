"""S12 baseline calculator: turn s12_probe CSV(s) into the numbers the S12 plan asks for.

Reads only local CSV files written by tools/s12_probe.py (ts_kst,label,source,status,ms,error).
No network access, standard library only. Prints a JSON summary.

Formulas follow team_docs/S12-진행계획-D-chacha1650a.md (D provisional plan):
  exceed threshold (ms) = max(p95 * 3, p95 + 300)
  request threshold N   = ceil(3 * max requests seen in any 60 s window)
With --received, D's unique web.request count for the same source and period is
compared with B's sent count. This count difference alone does not locate or
prove network loss. Same-run, nonoverlapping CSV parts may be combined.
"""
import argparse
import csv
import ipaddress
import json
import math
from pathlib import Path
import statistics
import sys
from datetime import datetime


def load(paths):
    rows = []
    seen_paths, seen_times, labels, sources = set(), set(), set(), set()
    for p in paths:
        path = Path(p).resolve()
        if path in seen_paths:
            raise ValueError('duplicate CSV input')
        seen_paths.add(path)
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fields = reader.fieldnames or []
            required = {'ts_kst', 'label', 'status', 'ms', 'error'}
            if len(fields) != len(set(fields)) or set(fields) not in (required, required | {'source'}):
                raise ValueError('unsupported CSV header')
            previous = None
            for r in reader:
                if None in r or any(v is None for v in r.values()):
                    raise ValueError('missing/extra CSV columns')
                stamp = datetime.fromisoformat(r['ts_kst'])
                latency = float(r['ms'])
                status = int(r['status'])
                if stamp.utcoffset() is None:
                    raise ValueError('timestamp needs a timezone')
                if stamp in seen_times or (previous is not None and stamp <= previous):
                    raise ValueError('duplicate or out-of-order timestamp')
                previous = stamp
                seen_times.add(stamp)
                if not math.isfinite(latency) or latency < 0:
                    raise ValueError('latency must be finite and nonnegative')
                if status != 0 and not 100 <= status <= 599:
                    raise ValueError('invalid HTTP status')
                label, source = r['label'].strip(), r.get('source', '').strip()
                if not label:
                    raise ValueError('empty label')
                if source:
                    ipaddress.IPv4Address(source)
                labels.add(label)
                sources.add(source)
                if len(labels) > 1 or len(sources) > 1:
                    raise ValueError('mixed baseline labels or sources')
                rows.append({
                    "t": stamp,
                    "status": status,
                    "ms": latency,
                    "error": r.get("error", ""),
                })
    rows.sort(key=lambda r: r["t"])
    return rows


def pct(sorted_ms, p):
    # same rule as s12_probe: index int(n*p), clamped
    return sorted_ms[min(len(sorted_ms) - 1, int(len(sorted_ms) * p))]


def spikes(rows, slow_ms=1000.0):
    """Requests that took long (>= slow_ms) or failed, as (start_kst, status, ms)."""
    return [(r["t"].isoformat(timespec="milliseconds"), r["status"], round(r["ms"], 1))
            for r in rows if not 200 <= r["status"] < 400 or r["error"] or r["ms"] >= slow_ms]


def max_in_window(times, seconds=60.0):
    """Largest number of requests inside any window of `seconds` (sliding)."""
    best, lo = 0, 0
    for hi, t in enumerate(times):
        while (t - times[lo]).total_seconds() >= seconds:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def summarize(rows, received=None):
    if not rows:
        raise SystemExit("no rows")
    if received is not None and (type(received) is not int or not 0 <= received <= len(rows)):
        raise SystemExit('received must be a unique request count between 0 and sent count')
    ok = sorted(r["ms"] for r in rows if 200 <= r["status"] < 400 and not r["error"])
    if not ok:
        raise SystemExit("no successful requests, cannot compute a baseline")
    times = [r["t"] for r in rows]
    p95 = pct(ok, 0.95)
    per_min = max_in_window(times)
    span = (times[-1] - times[0]).total_seconds()
    slow = spikes(rows)
    out = {
        "n": len(rows),
        "ok": len(ok),
        "failed": len(rows) - len(ok),
        "ok_over_3000ms": sum(1 for r in rows if 200 <= r["status"] < 400 and not r["error"] and r["ms"] > 3000),
        "slow_ge_1000ms_or_failed": len(slow),
        "slow_list": slow[:50],
        "first_kst": times[0].isoformat(timespec="milliseconds"),
        "last_kst": times[-1].isoformat(timespec="milliseconds"),
        "span_s": round(span, 1),
        "median_ms": round(statistics.median(ok), 1),
        "p95_ms": round(p95, 1),
        "p99_ms": round(pct(ok, 0.99), 1),
        "max_ms": round(max(ok), 1),
        "exceed_threshold_ms": round(max(p95 * 3, p95 + 300), 1),
        "max_requests_per_60s": per_min,
        "request_threshold_N": math.ceil(3 * per_min),
    }
    if received is not None:
        out["received_by_d"] = received
        out["lost"] = len(rows) - received
        out["loss_pct"] = round(100.0 * (len(rows) - received) / len(rows), 2)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("csv", nargs="+", help="s12_probe CSV file(s) of one baseline run")
    ap.add_argument("--received", type=int, default=None,
                    help="unique web.request count D saw for the same source and period (0..sent)")
    a = ap.parse_args(argv)
    if a.received is not None and a.received < 0:
        raise SystemExit("--received must be >= 0")
    try:
        result = summarize(load(a.csv), a.received)
    except (ValueError, OSError, OverflowError) as exc:
        ap.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main(sys.argv[1:])
