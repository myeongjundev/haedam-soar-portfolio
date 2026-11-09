"""Validated offline normal-client measurements; never changes incident status."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import ipaddress
import json
import math
from pathlib import Path
import statistics

KST = timezone(timedelta(hours=9))
REQUIRED = {"ts_kst", "label", "status", "ms", "error"}


def percentile(values, p):
    """Nearest-rank percentile, including the p=1 endpoint; empty => None."""
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)] if values else None


def read_run(path, expected_status=200):
    path = Path(path)
    if path.stat().st_size > 10_000_000:
        raise ValueError("CSV exceeds 10 MB")
    raw = path.read_bytes()
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
    fields = reader.fieldnames or []
    if len(fields) != len(set(fields)) or set(fields) not in (REQUIRED, REQUIRED | {"source"}):
        raise ValueError(f"{path.name}: unsupported CSV header")
    rows = []
    labels, sources = set(), set()
    missing_source = 0
    for line, row in enumerate(reader, 2):
        if line > 50001:
            raise ValueError("CSV exceeds 50000 requests")
        try:
            if None in row or any(v is None for v in row.values()):
                raise ValueError("missing/extra columns")
            stamp = datetime.fromisoformat(row["ts_kst"])
            if stamp.utcoffset() is None:
                raise ValueError("timestamp needs a timezone")
            stamp = stamp.astimezone(KST)
            if rows and stamp <= rows[-1]["timestamp"]:
                raise ValueError("duplicate or out-of-order timestamp")
            status, ms = int(row["status"]), float(row["ms"])
            if status != 0 and not 100 <= status <= 599:
                raise ValueError("invalid HTTP status")
            if not math.isfinite(ms) or ms < 0:
                raise ValueError("latency must be finite and nonnegative")
            stamp + timedelta(milliseconds=ms)  # reject unrepresentable completion times
            label, error, source = row["label"].strip(), row["error"].strip(), row.get("source", "").strip()
            if not label:
                raise ValueError("empty label")
            if status == 0 and not error:
                raise ValueError("status 0 needs an error reason")
            if source:
                ipaddress.IPv4Address(source)
                sources.add(source)
            else:
                missing_source += 1
            labels.add(label)
            rows.append({"timestamp": stamp, "status": status, "ms": ms,
                         "error": error, "ok": status == expected_status and not error})
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"{path.name}:{line}: {exc}") from exc
    if not rows:
        raise ValueError(f"{path.name}: no samples")
    if len(labels) != 1 or len(sources) > 1:
        raise ValueError(f"{path.name}: mixed labels or sources; split independent runs")
    good = [r["ms"] for r in rows if r["ok"]]
    longest = consecutive = 0
    for row in rows:
        consecutive = 0 if row["ok"] else consecutive + 1
        longest = max(longest, consecutive)
    gaps = [(b["timestamp"] - a["timestamp"]).total_seconds() for a, b in zip(rows, rows[1:])]
    # A request timestamp is its START, not completion. Never claim the requested
    # duration was fulfilled based on a count or the final start timestamp alone.
    end = max(r["timestamp"] + timedelta(milliseconds=r["ms"]) for r in rows)
    span = (end - rows[0]["timestamp"]).total_seconds()
    source = next(iter(sources), None)
    return {
        "file": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
        "label": next(iter(labels)), "source_recorded": source, "source_missing_samples": missing_source,
        "started_at": rows[0]["timestamp"].isoformat(), "last_started_at": rows[-1]["timestamp"].isoformat(),
        "last_completion_estimate": end.isoformat(), "observed_span_seconds": round(span, 3),
        "sample_count": len(rows), "success_count": len(good), "failure_count": len(rows) - len(good),
        "success_percent": round(len(good) / len(rows) * 100, 3),
        "failure_percent": round((len(rows) - len(good)) / len(rows) * 100, 3),
        "longest_failure_streak_samples": longest,
        "successful_latency_ms": {"median": statistics.median(good) if good else None,
                                  "p95": percentile(good, .95), "p99": percentile(good, .99),
                                  "max": max(good) if good else None},
        "start_gap_seconds": {"median": statistics.median(gaps) if gaps else None,
                              "max": max(gaps) if gaps else None},
        "status_counts": dict(sorted(Counter(str(r["status"]) for r in rows).items())),
        "error_counts": dict(sorted(Counter(r["error"] for r in rows if r["error"]).items())),
        "warnings": [] if not missing_source else [f"{missing_source}개 표본에 출발지 증거가 없습니다. 원본 시험 기록과 대조하세요."],
        "samples": [{"started_at": r["timestamp"].isoformat(), "status": r["status"],
                     "ms": r["ms"], "error": r["error"], "success": r["ok"]} for r in rows],
    }



TEXT_FIELDS = ("run_id", "ticket_id", "target", "route", "load_profile", "before_version", "after_version")
NUMBER_FIELDS = ("interval_seconds", "timeout_seconds", "duration_seconds")
FIELDS = set(TEXT_FIELDS) | set(NUMBER_FIELDS) | {"origin", "expected_status"}


def validate_metadata(meta):
    if not isinstance(meta, dict) or set(meta) != FIELDS:
        raise ValueError("metadata fields must match the S12 comparison contract")
    for key in TEXT_FIELDS:
        value = meta[key]
        if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > 300 or any(ord(c) < 32 for c in value):
            raise ValueError(f"invalid {key}")
    if meta["origin"] not in ("live", "sample") or meta["route"] not in ("portal", "pfsense"):
        raise ValueError("invalid origin or response route")
    if type(meta["expected_status"]) is not int or not 200 <= meta["expected_status"] <= 299:
        raise ValueError("expected_status must be an explicit 2xx code")
    for key in NUMBER_FIELDS:
        value = meta[key]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 86400:
            raise ValueError(f"invalid {key}")
    from urllib.parse import urlsplit
    url = urlsplit(meta["target"])
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("target must be an HTTP URL without credentials, query or fragment")


def import_comparison(conn, meta, before_path, after_path):
    """All validation precedes an atomic insert. Run IDs are immutable."""
    from . import db
    validate_metadata(meta)
    ticket = db.get_ticket(conn, meta["ticket_id"])
    if ticket["case_id"] != "S12" or ticket["data_origin"] != meta["origin"]:
        raise ValueError("S12 ticket and evidence origin must match")
    before, after = [read_run(p, meta["expected_status"]) for p in (before_path, after_path)]
    if before["sha256"] == after["sha256"]:
        raise ValueError("before and after cannot be the same CSV")
    if (before["source_missing_samples"] or after["source_missing_samples"] or
            not before["source_recorded"] or before["source_recorded"] != after["source_recorded"]):
        raise ValueError("both runs require the same recorded normal-client source")
    if before["source_recorded"] == ticket.get("src_ip"):
        raise ValueError("normal-client source cannot be the incident attack source")
    if datetime.fromisoformat(before["last_completion_estimate"]) > datetime.fromisoformat(after["started_at"]):
        raise ValueError("before and after measurement windows overlap or are reversed")
    if before["label"] == after["label"]:
        raise ValueError("use distinct before/after labels")
    # Probe timestamps are starts; expose deviations, do not silently normalize counts or windows.
    warnings = ["대상·부하·간격·제한시간·버전은 등록자가 선언한 조건입니다. CSV만으로 동일 조건을 증명하지 않습니다."]
    for phase, run in (("보강 전", before), ("보강 후", after)):
        if run["sample_count"] < 20:
            warnings.append(f"{phase}: 20개 미만의 표본입니다. p95 해석에 주의하세요.")
        if run["observed_span_seconds"] < meta["duration_seconds"] * .9:
            warnings.append(f"{phase}: 관측 구간이 선언한 측정 시간의 90%보다 짧습니다.")
        if run["start_gap_seconds"]["max"] and run["start_gap_seconds"]["max"] > meta["interval_seconds"] * 1.5:
            warnings.append(f"{phase}: 요청 시작 간격이 선언 주기를 크게 초과했습니다.")
    if before["sample_count"] != after["sample_count"]:
        warnings.append("전후 요청 수가 다릅니다. 성공률의 분모와 관측 구간을 함께 확인하세요.")
    bm, am = before["successful_latency_ms"]["median"], after["successful_latency_ms"]["median"]
    for run in (before, after):
        run.pop("samples")  # Retain file hash and aggregate evidence; originals stay with the operator.
    payload = {"metadata": meta, "before": before, "after": after, "warnings": warnings,
               "success_delta_pp": round(after["success_percent"] - before["success_percent"], 3),
               "median_delta_ms": None if bm is None or am is None else am - bm}
    with conn:
        conn.execute("INSERT INTO s12_comparisons VALUES (?, ?, ?, ?, ?)",
                     (meta["run_id"], meta["ticket_id"], meta["origin"], db.now_iso(),
                      json.dumps(payload, ensure_ascii=False, allow_nan=False)))
    return payload


def comparisons(conn, *, ticket_id=None, include_sample=False, run_id=None):
    where, args = [], []
    if ticket_id:
        where.append("ticket_id = ?")
        args.append(ticket_id)
    if not include_sample:
        where.append("data_origin = 'live'")
    if run_id:
        where.append("run_id = ?")
        args.append(run_id)
    sql = "SELECT payload FROM s12_comparisons" + (" WHERE " + " AND ".join(where) if where else "")
    rows = conn.execute(sql + " ORDER BY recorded_at DESC, rowid DESC LIMIT 50", args).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True)
    ap.add_argument("--metadata", required=True)
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    args = ap.parse_args()
    # A typo must not create a new empty production database.
    if not Path(args.db).is_file():
        ap.error("existing ticket database required")
    from contextlib import closing
    from . import db
    import sqlite3
    try:
        meta = json.loads(Path(args.metadata).read_text(encoding="utf-8-sig"))
        with closing(db.connect(args.db)) as conn:
            import_comparison(conn, meta, args.before, args.after)
        print("Registered S12 comparison:", meta["run_id"])
    except (ValueError, OSError, sqlite3.Error, db.NotFound) as exc:
        ap.error(str(exc))


if __name__ == "__main__":
    main()
