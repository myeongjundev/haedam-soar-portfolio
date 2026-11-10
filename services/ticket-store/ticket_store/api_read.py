"""Dashboard read API (127.0.0.1:8089 only, no key). Design section 6-6."""
from contextlib import closing

from flask import Blueprint, current_app, jsonify, request

from . import db

bp = Blueprint("api_read", __name__, url_prefix="/api/v1/tickets")


def conn():
    return current_app.extensions["ticket_store_conn"]()


def error(status, code, message):
    return jsonify(ok=False, error={"code": code, "message": message}), status


@bp.get("")
def list_tickets():
    statuses = [s for s in request.args.get("status", "").split(",") if s]
    if any(s not in db.STATUSES for s in statuses):
        return error(400, "VALIDATION_ERROR", "status must be a comma list of " + ", ".join(db.STATUSES))
    try:
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
    except ValueError:
        return error(400, "VALIDATION_ERROR", "limit must be a number")
    include_sample = request.args.get("sample") == "1"
    with closing(conn()) as c:
        items = db.list_tickets(c, seat=request.args.get("seat") or None, case_id=request.args.get("case_id") or None,
                                statuses=statuses or None, include_sample=include_sample, limit=limit)
        return jsonify(ok=True, count=len(items), items=items, counts=db.status_counts(c, include_sample),
                       last_record_at=db.last_record_at(c))


@bp.get("/<ticket_id>")
def ticket_detail(ticket_id):
    with closing(conn()) as c:
        try:
            return jsonify(ok=True, ticket=db.get_ticket(c, ticket_id))
        except db.NotFound:
            return error(404, "NOT_FOUND", "ticket not found")
