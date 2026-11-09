"""Security dashboard screens (127.0.0.1:8089). Design section 6.

- GET /                     list page (6-1), filters in the query string
- GET /_list                list fragment the page reloads every 10 seconds (6-3)
- GET /tickets/<id>         detail page (6-2)
- POST /api/v1/tickets/<id>/close   human close (6-4): Origin + request token check
Times are shown in KST with the original ISO value on hover.
"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hmac
import secrets
import sqlite3

from flask import Blueprint, current_app, jsonify, render_template, request

from . import db, s12_measurements

bp = Blueprint("dashboard", __name__, template_folder="templates", static_folder="static",
               static_url_path="/static")

KST = timezone(timedelta(hours=9), "KST")
SEATS = ("A", "B", "C", "D")
CASES = ("S1", "S4", "S7", "S8", "S10", "S12")
OPEN_STATUSES = ("open", "responding", "verified", "restored")
STATUS_LABELS = {"open": "열림", "responding": "대응 중", "verified": "효과 확인", "restored": "원복", "closed": "종료"}
FAILED_RESULTS = ("failed", "rejected")
QUIET_MINUTES = 10
NOTE_MAX = 200
TIMELINE = (("first_attack_at", "첫 공격"), ("condition_met_at", "조건 충족"), ("detected_at", "판정"),
            ("received_at", "n8n 수신"), ("created_at", "티켓 생성"), ("responded_at", "조치 완료"), ("verified_at", "효과 확인"),
            ("restored_at", "원복"), ("closed_at", "종료"))


@bp.record_once
def _setup(state):
    # One random token per process. Other sites cannot read the page, so they cannot learn it.
    state.app.config.setdefault("DASHBOARD_TOKEN", secrets.token_urlsafe(32))
    state.app.jinja_env.filters["kst"] = kst
    state.app.jinja_env.filters["duration"] = duration
    state.app.jinja_env.globals.update(STATUS_LABELS=STATUS_LABELS, FAILED_RESULTS=FAILED_RESULTS)


@bp.after_request
def _security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def conn():
    return current_app.extensions["ticket_store_conn"]()


def now_kst():
    return datetime.now(KST)


def kst(value, fmt="%m-%d %H:%M:%S"):
    if not value:
        return "—"
    return datetime.fromisoformat(value).astimezone(KST).strftime(fmt)


def duration(seconds):
    if seconds is None:
        return "—"
    seconds = round(seconds)
    sign = "-" if seconds < 0 else ""
    minutes, sec = divmod(abs(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{sign}{hours}시간 {minutes}분"
    return f"{sign}{minutes}분 {sec}초" if minutes else f"{sign}{sec}초"


def read_filters(args):
    status = args.get("status", "")
    return {
        "seat": args.get("seat") if args.get("seat") in SEATS else "",
        "case_id": args.get("case_id") if args.get("case_id") in CASES else "",
        "status": status if status in (*db.STATUSES, "all") else "",
        "sample": args.get("sample") == "1",
    }


def connection_badge(c, last):
    """6-3: real connection, quiet n8n, sample only or nothing received yet."""
    if last:
        minutes = int((now_kst() - datetime.fromisoformat(last)).total_seconds() // 60)
        if minutes >= QUIET_MINUTES:
            return {"kind": "quiet", "text": f"n8n 수신 없음 {minutes}분"}
        return {"kind": "live", "text": f"실제 연결 · 마지막 수신 {kst(last, '%H:%M:%S')}"}
    live = sum(db.status_counts(c, False).values())
    if live:
        return {"kind": "live", "text": "실제 연결 · 수신 시각 없음"}
    if sum(db.status_counts(c, True).values()):
        return {"kind": "sample", "text": "샘플 데이터"}
    return {"kind": "none", "text": "수신 기록 없음"}


def list_view(args):
    f = read_filters(args)
    statuses = None if f["status"] == "all" else [f["status"]] if f["status"] else list(OPEN_STATUSES)
    with closing(conn()) as c:
        items = db.list_tickets(c, seat=f["seat"] or None, case_id=f["case_id"] or None, statuses=statuses,
                                include_sample=f["sample"], limit=200)
        counts = db.status_counts(c, f["sample"])
        today = now_kst().date()
        origin_clause = "" if f["sample"] else " WHERE data_origin = 'live'"
        # Aggregate in KST in SQLite; never derive totals from the capped queue.
        daily = c.execute(
            "SELECT date(created_at, '+9 hours') AS day, COUNT(*) AS count FROM tickets"
            + origin_clause + " GROUP BY day"
        ).fetchall()
        by_day = {row["day"]: row["count"] for row in daily}
        trend = [{"day": (today - timedelta(days=i)).isoformat(),
                  "label": (today - timedelta(days=i)).strftime('%m/%d'),
                  "count": by_day.get((today - timedelta(days=i)).isoformat(), 0)}
                 for i in range(6, -1, -1)]
        peak = max((row["count"] for row in trend), default=0) or 1
        for row in trend:
            row["height"] = round(row["count"] / peak * 100, 2)
        closed_today = c.execute(
            "SELECT COUNT(*) FROM tickets WHERE status = 'closed' AND date(closed_at, '+9 hours') = ?"
            + ("" if f["sample"] else " AND data_origin = 'live'"), (today.isoformat(),)
        ).fetchone()[0]
        last = db.last_record_at(c)
        # Exact open-ticket distribution, independent of the 200-row queue limit.
        groups = c.execute(
            "SELECT seat, case_id, COUNT(*) AS count FROM tickets WHERE status != 'closed'"
            + ("" if f["sample"] else " AND data_origin = 'live'")
            + " GROUP BY seat, case_id"
        ).fetchall()
        distributions = []
        for key, label, values in (("case_id", "케이스별 사건", CASES), ("seat", "자리별 사건", SEATS)):
            buckets = {value: 0 for value in values}
            for row in groups:
                buckets[row[key]] = buckets.get(row[key], 0) + row["count"]
            maximum = max(buckets.values(), default=0)
            distributions.append({"key": key, "label": label, "maximum": maximum or 1, "rows": [
                {"label": value, "count": count}
                for value, count in buckets.items()
            ]})
        return {"filters": f, "tickets": items, "counts": counts, "closed_today": closed_today,
                "case_rows": db.dashboard_cases(c, f["seat"] or None, f["sample"]),
                "distributions": distributions, "trend": trend, "scoped_total": sum(counts.values()),
                "open_total": sum(counts[s] for s in OPEN_STATUSES),
                "total": sum(db.status_counts(c, True).values()), "last_record_at": last,
                "badge": connection_badge(c, last), "refreshed_at": now_kst().strftime("%H:%M:%S")}


@bp.get("/")
def index():
    try:
        view, failed = list_view(request.args), None
    except sqlite3.Error:
        view, failed = None, now_kst().strftime("%H:%M:%S")
    return render_template("list.html", view=view, failed=failed, filters=read_filters(request.args),
                           seats=SEATS, cases=CASES, statuses=db.STATUSES, query=request.query_string.decode())


@bp.get("/_list")
def list_fragment():
    try:
        return render_template("_list.html", view=list_view(request.args), seats=SEATS, cases=CASES,
                               statuses=db.STATUSES)
    except sqlite3.Error:
        return error(503, "SERVER_ERROR", "ticket store read failed")


def display_duration(start, end):
    if not start or not end:
        return "미측정"
    try:
        seconds = db.seconds_between(start, end)
        return duration(seconds) if seconds >= 0 else "시각 확인 필요"
    except (ValueError, TypeError, OverflowError):
        return "시각 확인 필요"


def timeline(ticket):
    steps = [{"label": label, "field": field, "at": ticket.get(field)} for field, label in TIMELINE]
    gaps = {
        "detected_at": ("MTTD", display_duration(ticket["condition_met_at"], ticket["detected_at"])),
        "verified_at": ("MTTR", display_duration(ticket["detected_at"], ticket["verified_at"])),
        "restored_at": ("효과 확인→원복 기록", display_duration(ticket["verified_at"], ticket["restored_at"])),
    }
    for step in steps:
        if step["field"] in gaps:
            step["gap"] = gaps[step["field"]]
    return steps


@bp.get("/tickets/<ticket_id>")
def detail(ticket_id):
    with closing(conn()) as c:
        try:
            ticket = db.dashboard_ticket(c, ticket_id, page=page_number())
        except db.NotFound:
            return render_template("missing.html", ticket_id=ticket_id), 404
    last = ticket["last_result"]
    with closing(conn()) as c:
        active = db.dashboard_has_active(c, ticket_id)
        measurements = s12_measurements.comparisons(c, ticket_id=ticket_id, include_sample=ticket['data_origin'] == 'sample')
    return render_template("detail.html", ticket=ticket, steps=timeline(ticket), last_result=last, active_action=active,
                           closable=ticket["status"] in db.CLOSABLE and not active, note_max=NOTE_MAX,
                           measurements=measurements)


@bp.get('/s12')
def s12_comparison():
    include_sample = request.args.get('sample') == '1'
    with closing(conn()) as c:
        options = s12_measurements.comparisons(c, include_sample=include_sample)
        run_id = request.args.get('run', '')
        rows = s12_measurements.comparisons(c, include_sample=include_sample, run_id=run_id) if run_id else options[:1]
    return render_template('s12.html', measurements=rows, options=options, selected=run_id,
                           include_sample=include_sample)


def error(status, code, message):
    return jsonify(ok=False, error={"code": code, "message": message}), status


@bp.post("/api/v1/tickets/<ticket_id>/close")
def close(ticket_id):
    if request.headers.get("Origin") != current_app.config["DASHBOARD_ORIGIN"]:
        return error(403, "FORBIDDEN", "close is only allowed from the dashboard page")
    token = request.headers.get("X-Dashboard-Token", "")
    if not hmac.compare_digest(token.encode(), current_app.config["DASHBOARD_TOKEN"].encode()):
        return error(403, "FORBIDDEN", "missing or wrong dashboard token")
    body = request.get_json(silent=True)
    note = body.get("note") if isinstance(body, dict) else None
    if not isinstance(note, str) or not note.strip() or len(note.strip()) > NOTE_MAX:
        return error(400, "VALIDATION_ERROR", f"note must be 1-{NOTE_MAX} characters")
    with closing(conn()) as c:
        try:
            return jsonify(ok=True, ticket=db.close_ticket(c, ticket_id, note.strip()))
        except db.NotFound:
            return error(404, "NOT_FOUND", "ticket not found")
        except db.InvalidTransition:
            status = db.get_ticket(c, ticket_id)["status"]
            if status in db.CLOSABLE:
                return error(409, "INVALID_TRANSITION", "an applied action is not released yet; release it before closing")
            return error(409, "INVALID_TRANSITION",
                         f"only verified or restored tickets can be closed (now {status})")


def _write_guard():
    """Same Origin and token rule as close(); returns an error response or None."""
    if request.headers.get("Origin") != current_app.config["DASHBOARD_ORIGIN"]:
        return error(403, "FORBIDDEN", "this action is only allowed from the dashboard page")
    token = request.headers.get("X-Dashboard-Token", "")
    if not hmac.compare_digest(token.encode(), current_app.config["DASHBOARD_TOKEN"].encode()):
        return error(403, "FORBIDDEN", "missing or wrong dashboard token")
    return None


@bp.post("/api/v1/tickets/<ticket_id>/cancel")
def cancel(ticket_id):
    """Cancel an open live test ticket that never acted (db.cancel_ticket). 127.0.0.1 only, like close."""
    refused = _write_guard()
    if refused:
        return refused
    body = request.get_json(silent=True)
    note = body.get("note") if isinstance(body, dict) else None
    limit = NOTE_MAX - len(db.CANCEL_PREFIX)   # the stored close_note carries the prefix
    if not isinstance(note, str) or not note.strip() or len(note.strip()) > limit:
        return error(400, "VALIDATION_ERROR", f"note must be 1-{limit} characters")
    with closing(conn()) as c:
        try:
            return jsonify(ok=True, ticket=db.cancel_ticket(c, ticket_id, note.strip()))
        except db.NotFound:
            return error(404, "NOT_FOUND", "ticket not found")
        except db.InvalidTransition as exc:
            return error(409, "INVALID_TRANSITION", str(exc))


def page_number():
    try:
        return min(max(int(request.args.get("page", "1")), 1), 10000)
    except ValueError:
        return 1


def _screen_view(kind):
    filters = read_filters(request.args)
    with closing(conn()) as c:
        rows = db.dashboard_cases(c, filters["seat"] or None, filters["sample"]) if kind == "cases" else db.dashboard_work(c, filters["seat"] or None, filters["sample"], page_number())
        last = db.last_record_at(c)
    return {"rows": rows, "filters": filters, "refreshed_at": now_kst().strftime("%H:%M:%S"), "last_record_at": last}


@bp.get("/cases")
def cases():
    try:
        view = _screen_view("cases")
    except sqlite3.Error:
        view = None
    return render_template("cases.html", view=view, filters=read_filters(request.args), seats=SEATS)


@bp.get("/_cases")
def cases_fragment():
    try:
        return render_template("_cases.html", view=_screen_view("cases"))
    except sqlite3.Error:
        return error(503, "SERVER_ERROR", "ticket store read failed")


@bp.get("/work")
def work():
    try:
        view = _screen_view("work")
    except sqlite3.Error:
        view = None
    return render_template("work.html", view=view, filters=read_filters(request.args), seats=SEATS)


@bp.get("/_work")
def work_fragment():
    try:
        return render_template("_work.html", view=_screen_view("work"))
    except sqlite3.Error:
        return error(503, "SERVER_ERROR", "ticket store read failed")
