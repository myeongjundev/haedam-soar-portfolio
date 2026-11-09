"""Record request checks mirroring contracts/ticket-record.schema.json.

Length limits on asset_id/username (300) are a little stricter than the contract.

The container has no jsonschema, so these rules are hand-written;
tests/test_ticket_store_core.py checks they accept and reject the same
bodies as the contract.
"""
from datetime import datetime
import ipaddress
import re

SEATS = ("A", "B", "C", "D")
CASES = ("S1", "S4", "S7", "S8", "S10", "S12", "H1")
STAGES = ("detected", "applied", "effect", "released")
VIA = ("portal", "wazuh-ar", "pfsense", "manual")
RESULTS = ("applied", "already_applied", "failed", "rejected", "released")
TOP = {"seat", "case_id", "group_key", "stage", "title", "asset_id", "src_ip", "username", "event_ids", "reason",
       "first_attack_at", "condition_met_at", "detected_at", "received_at", "action"}
ACTION = {"bot", "target", "via", "action", "result", "applied_verified", "effect_verified", "requested_at",
          "finished_at", "effect_verified_at", "n8n_execution_id", "detail"}
ACTION_REQUIRED = ACTION - {"detail"}
NO_CONTROL = re.compile(r"^[^\x00-\x1f\x7f]+$")
IDEMPOTENCY_KEY = re.compile(r"^[!-~]{8,100}$")


class Invalid(Exception):
    """Message names the field only; never the received value."""


def _str(value, name, max_len, pattern=None):
    if not isinstance(value, str) or not 1 <= len(value) <= max_len or (pattern and not pattern.match(value)):
        raise Invalid(f"{name} is invalid")


def _time(value, name):
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) and "T" in value else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        raise Invalid(f"{name} must be ISO 8601 with a time zone")


def _bool_or_none(value, name):
    if value is not None and not isinstance(value, bool):
        raise Invalid(f"{name} must be true, false or null")


def idempotency_key(value):
    if not value or not IDEMPOTENCY_KEY.match(value):
        raise Invalid("Idempotency-Key must be 8-100 printable characters")


def resource_query(args):
    """Exact scope required: an incomplete/ambiguous query must not mean zero claims."""
    fields = {"asset_id", "via", "action", "target"}
    if set(args) != fields or any(len(args.getlist(name)) != 1 for name in fields):
        raise Invalid("active query requires exactly asset_id, via, action and target")
    resource = {name: args[name] for name in sorted(fields)}
    for name in ("asset_id", "target"):
        _str(resource[name], name, 300, NO_CONTROL)
    if resource["via"] not in VIA:
        raise Invalid("via is invalid")
    if not re.fullmatch(r"[a-z][a-z_]{1,31}", resource["action"]):
        raise Invalid("action is invalid")
    return resource


def record_body(body):
    if not isinstance(body, dict):
        raise Invalid("body must be a JSON object")
    extra = set(body) - TOP
    if extra:
        raise Invalid(f"unknown field: {sorted(extra)[0]}")
    for name in ("seat", "case_id", "group_key", "stage", "title", "asset_id", "event_ids", "action"):
        if name not in body:
            raise Invalid(f"{name} is required")
    if body["seat"] not in SEATS:
        raise Invalid("seat must be one of A, B, C, D")
    if body["case_id"] not in CASES:
        raise Invalid("case_id is invalid")
    if body["stage"] not in STAGES:
        raise Invalid("stage must be one of " + ", ".join(STAGES))
    _str(body["group_key"], "group_key", 300, NO_CONTROL)
    _str(body["title"], "title", 200)
    _str(body["asset_id"], "asset_id", 300)
    if "reason" in body:
        _str(body.get("reason"), "reason", 500)
    if body.get("username") is not None:
        _str(body["username"], "username", 300)
    if body.get("src_ip") is not None:
        try:
            ipaddress.ip_address(body["src_ip"])
        except (ValueError, TypeError):
            raise Invalid("src_ip is invalid") from None
    ids = body["event_ids"]
    if (not isinstance(ids, list) or not ids or len(set(map(str, ids))) != len(ids)
            or not all(isinstance(i, str) and i for i in ids)):
        raise Invalid("event_ids must be a non-empty list of unique strings")
    for name in ("first_attack_at", "condition_met_at", "detected_at", "received_at"):
        _time(body.get(name), name)
    action = body["action"]
    if body["stage"] == "detected":
        if action is not None:
            raise Invalid("action must be null when stage is detected")
        return
    _action(action)
    if body["stage"] == "effect" and (not isinstance(action["effect_verified"], bool) or action["effect_verified_at"] is None):
        raise Invalid("effect stage needs effect_verified and effect_verified_at")
    if body["stage"] == "released" and action["result"] != "released":
        raise Invalid("released stage needs result released")


def _action(action):
    if not isinstance(action, dict):
        raise Invalid("action must be an object for this stage")
    extra = set(action) - ACTION
    if extra:
        raise Invalid(f"unknown action field: {sorted(extra)[0]}")
    missing = ACTION_REQUIRED - set(action)
    if missing:
        raise Invalid(f"action.{sorted(missing)[0]} is required")
    if not isinstance(action["bot"], str) or not re.fullmatch(r"[0-9]{3}|manual", action["bot"]):
        raise Invalid("action.bot must be a 3-digit string or manual")
    _str(action["target"], "action.target", 300, NO_CONTROL)
    if action["via"] not in VIA:
        raise Invalid("action.via must be one of " + ", ".join(VIA))
    if not isinstance(action["action"], str) or not re.fullmatch(r"[a-z][a-z_]{1,31}", action["action"]):
        raise Invalid("action.action is invalid")
    if action["result"] not in RESULTS:
        raise Invalid("action.result must be one of " + ", ".join(RESULTS))
    _bool_or_none(action["applied_verified"], "action.applied_verified")
    _bool_or_none(action["effect_verified"], "action.effect_verified")
    for name in ("requested_at", "finished_at", "effect_verified_at"):
        _time(action[name], f"action.{name}")
    _str(action["n8n_execution_id"], "action.n8n_execution_id", 64)
    if "detail" in action and (not isinstance(action["detail"], str) or len(action["detail"]) > 300):
        raise Invalid("action.detail is invalid")
