import json
import socket
from datetime import timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ATTACKER, NORMAL = "203.0.113.11", "203.0.113.100"


def respond(app, method, path, data=None, key=None, addr="127.0.0.1"):
    headers = {"X-Response-Key": app.config["RESPONSE_API_KEY"]}
    if key:
        headers["Idempotency-Key"] = key
    return app.test_client().open("/api/v1/response" + path, method=method, json=data, headers=headers,
                                  environ_overrides={"REMOTE_ADDR": addr})


def visit(app, path, addr, **headers):
    return app.test_client().get(path, headers=headers, environ_overrides={"REMOTE_ADDR": addr})


def events(app):
    lines = Path(app.config["EVENT_LOG_PATH"]).read_text(encoding="utf-8").splitlines()
    result = [json.loads(line) for line in lines]
    schema = json.loads((Path(__file__).resolve().parents[1] / "contracts/portal-event.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for event in result:
        validator.validate(event)
    return result


def frontend(app):
    dist = Path(app.config["FRONTEND_DIST"])
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>해담시청</title>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('haedam')", encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")


def test_blocked_source_is_refused_on_every_path_and_unblock_restores_it(app):
    frontend(app)
    blocked = respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="block-attacker-01")
    assert blocked.status_code == 200
    assert blocked.json["data"] == {"ip": ATTACKER, "blocked": True, "changed": True, "expires_at": None}
    for path in ["/api/v1/health", "/", "/assets/app.js", "/no-such-page"]:
        response = visit(app, path, ATTACKER)
        assert response.status_code == 403, path
        assert response.json["error"]["code"] == "IP_BLOCKED"
    # A spoofed forwarding header neither escapes the block nor blocks a normal user.
    assert visit(app, "/api/v1/health", ATTACKER, **{"X-Forwarded-For": NORMAL}).status_code == 403
    assert visit(app, "/api/v1/health", NORMAL, **{"X-Forwarded-For": ATTACKER}).status_code == 200
    unblocked = respond(app, "POST", "/ips/unblock", {"ip": ATTACKER}, key="unblock-attacker-01")
    assert unblocked.json["data"] == {"ip": ATTACKER, "blocked": False, "changed": True, "expires_at": None}
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 200


def test_block_api_refuses_unauthorized_callers_protected_and_invalid_targets(app):
    assert respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="no-cidr-0001", addr="192.0.2.1").status_code == 403
    no_key = app.test_client().post("/api/v1/response/ips/block", json={"ip": ATTACKER}, headers={"Idempotency-Key": "no-key-0001"})
    assert no_key.status_code == 403
    # The response caller network must never lock itself out.
    assert respond(app, "POST", "/ips/block", {"ip": "127.0.0.9"}, key="self-block-01").status_code == 403
    assert visit(app, "/api/v1/health", "127.0.0.9").status_code == 200
    for bad in [{"ip": "not-an-ip"}, {"ip": ATTACKER, "minutes": 0}, {"ip": ATTACKER, "minutes": "5"}, {}]:
        response = respond(app, "POST", "/ips/block", bad, key="bad-input-0001")
        assert response.status_code == 400 and response.json["error"]["code"] == "VALIDATION_ERROR", bad
    assert respond(app, "POST", "/ips/drop", {"ip": ATTACKER}, key="bad-action-01").status_code == 404
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 200


def test_block_replays_by_idempotency_key_and_lists_current_state(app):
    first = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="block-retry-0001")
    assert first.status_code == 200 and first.json["data"]["changed"] is True
    assert first.json["data"]["expires_at"].endswith("Z")
    assert respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="block-retry-0001").json == first.json
    assert respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 60}, key="block-retry-0001").status_code == 409
    again = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 10}, key="block-again-0001")
    assert again.json["data"]["changed"] is False
    listed = respond(app, "GET", "/ips")
    assert listed.status_code == 200
    assert [item["ip"] for item in listed.json["data"]["items"]] == [ATTACKER]
    assert respond(app, "GET", "/ips", addr="192.0.2.1").status_code == 403


def test_shorter_block_with_another_key_keeps_the_open_ended_block(app):
    first = respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="overlap-open-0001")
    shorter = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="overlap-30m-0001")
    assert shorter.json["data"] == {"ip": ATTACKER, "blocked": True, "changed": False, "expires_at": None}
    assert respond(app, "GET", "/ips").json["data"]["items"][0]["expires_at"] is None
    assert respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="overlap-open-0001").json == first.json


def test_open_ended_block_extends_a_timed_one_and_reports_the_change(app):
    timed = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="extend-30m-0001")
    longer = respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="extend-open-0001")
    assert longer.json["data"] == {"ip": ATTACKER, "blocked": True, "changed": True, "expires_at": None}
    assert respond(app, "GET", "/ips").json["data"]["items"][0]["expires_at"] is None
    # A replay returns that call's first response, not the current state.
    assert respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="extend-30m-0001").json == timed.json


def test_timed_blocks_keep_the_later_expiry(app, monkeypatch):
    from haedam_portal import integration, models
    # Past the half second: MySQL DATETIME would round an expiry with a fraction away from the response.
    clock = models.now().replace(microsecond=600000)
    monkeypatch.setattr(integration, "now", lambda: clock)
    short = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="timed-30m-00001")
    long = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 120}, key="timed-120m-0001")
    assert long.json["data"]["changed"] is True
    assert long.json["data"]["expires_at"] > short.json["data"]["expires_at"]
    again = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="timed-30m-00002")
    assert again.json["data"] == {**long.json["data"], "changed": False}
    assert respond(app, "GET", "/ips").json["data"]["items"][0]["expires_at"] == long.json["data"]["expires_at"]


def test_expired_block_no_longer_refuses_the_source(app):
    from haedam_portal.models import BlockedIp, db, now
    respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 5}, key="expire-test-01")
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 403
    with app.app_context():
        db.session.get(BlockedIp, ATTACKER).expires_at = now() - timedelta(seconds=1)
        db.session.commit()
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 200
    assert respond(app, "GET", "/ips").json["data"]["items"] == []


def test_ipv4_mapped_address_is_treated_as_the_same_source(app):
    respond(app, "POST", "/ips/block", {"ip": "::ffff:" + ATTACKER}, key="mapped-block-01")
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 403
    assert respond(app, "GET", "/ips").json["data"]["items"][0]["ip"] == ATTACKER


def test_block_actions_and_refused_requests_are_logged(app):
    respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="log-block-0001")
    visit(app, "/api/v1/health", ATTACKER)
    respond(app, "POST", "/ips/unblock", {"ip": ATTACKER}, key="log-unblock-01")
    logged = events(app)
    actions = [(e["event_type"], e["src_ip"], e["details"]["target_ip"]) for e in logged if "target_ip" in e["details"]]
    assert actions == [("web.ip_blocked", "127.0.0.1", ATTACKER), ("web.ip_unblocked", "127.0.0.1", ATTACKER)]
    refused = [e for e in logged if e["src_ip"] == ATTACKER and e["event_type"] == "web.request"]
    assert [(e["outcome"], e["details"]["status"]) for e in refused] == [("denied", 403)]


def test_served_files_are_logged_with_web_root_file_keys(app):
    frontend(app)
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(2)
    app.config.update(GELF_ENABLED=True, GELF_HOST="127.0.0.1", GELF_PORT=receiver.getsockname()[1])
    try:
        for path, status in [("/assets/app.js?v=secret-token", 200), ("/", 200), ("/login", 200),
                             ("/favicon.svg", 200), ("/assets/missing.js", 404), ("/hacked.html", 404)]:
            assert visit(app, path, NORMAL).status_code == status, path
        gelf = []
        while True:
            try:
                gelf.append(json.loads(receiver.recv(65535)))
            except socket.timeout:
                break
    finally:
        receiver.close()
    logged = events(app)
    keys = [e["details"]["file_key"] for e in logged if e["event_type"] == "web.file_access"]
    assert keys == ["assets/app.js", "index.html", "index.html", "favicon.svg"]
    assert all("file_key" not in e["details"] for e in logged if e["event_type"] != "web.file_access")
    # Static files stay out of the per-source request count used by S12.
    assert not [e for e in logged if e["event_type"] == "web.request" and e["details"]["resource"].startswith("/assets")]
    assert "secret-token" not in json.dumps(logged)
    file_gelf = [(m["_rule"], m["_file_key"]) for m in gelf if m["_event_type"] == "web.file_access"]
    assert file_gelf[0] == ("file-access", "assets/app.js")


FILE_KEY_CASES = ["assets/app.js", "index.html", "favicon.svg", "assets/a..b.js", "assets/sub/app.js", "a" * 200, "a" * 201,
                  "assets/app.js?v=1", "assets/app.js#x", "assets/review#asset.js", "/assets/app.js", "assets" + chr(92) + "app.js",
                  "../secret", "assets/../x", "assets/./x.js", "assets//x.js", "assets/", "", "C:/Windows/system.ini",
                  "assets/\n../secret", "assets/review.js\n", "assets/a\x01b.js", "assets/a\x7fb.js"]


def test_file_key_rule_agrees_with_the_event_contract():
    from haedam_portal.common import file_key
    schema = json.loads((Path(__file__).resolve().parents[1] / "contracts/portal-event.schema.json").read_text(encoding="utf-8"))
    contract = Draft202012Validator(schema["properties"]["details"]["properties"]["file_key"])
    for key in FILE_KEY_CASES:
        assert (file_key(key) == key) is contract.is_valid(key), repr(key)
        assert file_key(key) in (key, None), repr(key)


def test_files_whose_key_breaks_the_contract_are_not_served_or_logged(app):
    frontend(app)
    (Path(app.config["FRONTEND_DIST"]) / "assets" / "review#asset.js").write_text("console.log('x')", encoding="utf-8")
    assert visit(app, "/assets/review%23asset.js", NORMAL).status_code == 404
    assert visit(app, "/assets/app.js", NORMAL).status_code == 200
    keys = [e["details"]["file_key"] for e in events(app) if e["event_type"] == "web.file_access"]
    assert keys == ["assets/app.js"]


def test_address_that_joins_the_response_network_is_reachable_and_unblockable(app):
    respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="before-cidr-01")
    app.config["RESPONSE_ALLOWED_CIDRS"] = ["127.0.0.0/8", "203.0.113.0/24"]
    # A stale block row must not lock the response network out.
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 200
    unblocked = respond(app, "POST", "/ips/unblock", {"ip": ATTACKER}, key="after-cidr-01")
    assert unblocked.status_code == 200 and unblocked.json["data"]["changed"] is True
    assert respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="after-cidr-02").status_code == 403


def interfere(app, statement_prefix, sql, params):
    """Commit `sql` from another connection right before the request runs its first `statement_prefix` statement."""
    from sqlalchemy import event, text
    from haedam_portal.models import db
    with app.app_context():
        engine = db.engine
    fired = []

    def hook(conn, cursor, statement, parameters, context, executemany):
        if not fired and statement.lstrip().upper().startswith(statement_prefix):
            fired.append(statement)
            with engine.begin() as other:
                other.execute(text(sql), params)

    event.listen(engine, "before_cursor_execute", hook)
    return lambda: event.remove(engine, "before_cursor_execute", hook) or fired


def test_first_block_that_loses_the_insert_race_reports_unchanged(app):
    from haedam_portal.models import now
    stop = interfere(app, "INSERT INTO BLOCKED_IPS", "INSERT INTO blocked_ips (ip, expires_at, created_at) VALUES (:ip, NULL, :at)",
                     {"ip": ATTACKER, "at": now().strftime("%Y-%m-%d %H:%M:%S")})
    try:
        result = respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="race-first-0001")
    finally:
        assert stop(), "the race was not staged"
    assert result.status_code == 200, result.json
    assert result.json["data"] == {"ip": ATTACKER, "blocked": True, "changed": False, "expires_at": None}
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 403


def test_block_refresh_that_races_an_unblock_blocks_again(app):
    respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 5}, key="refresh-base-01")
    stop = interfere(app, "UPDATE BLOCKED_IPS", "DELETE FROM blocked_ips WHERE ip = :ip", {"ip": ATTACKER})
    try:
        result = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="refresh-race-01")
    finally:
        assert stop(), "the race was not staged"
    assert result.status_code == 200, result.json
    assert result.json["data"]["changed"] is True
    assert visit(app, "/api/v1/health", ATTACKER).status_code == 403


def test_extension_that_races_an_open_ended_block_never_shortens_it(app):
    respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 5}, key="race-5m-0000001")
    # Another caller makes the block open-ended right before this request extends it to 30 minutes.
    stop = interfere(app, "UPDATE BLOCKED_IPS", "UPDATE blocked_ips SET expires_at = NULL WHERE ip = :ip", {"ip": ATTACKER})
    try:
        result = respond(app, "POST", "/ips/block", {"ip": ATTACKER, "minutes": 30}, key="race-30m-000001")
    finally:
        assert stop(), "the race was not staged"
    assert result.status_code == 200, result.json
    assert result.json["data"] == {"ip": ATTACKER, "blocked": True, "changed": False, "expires_at": None}
    assert respond(app, "GET", "/ips").json["data"]["items"][0]["expires_at"] is None


import pytest


@pytest.mark.parametrize("action,blocked_before", [("unblock", True), ("block", False)])
def test_concurrent_same_key_ip_requests_replay_one_result_on_mysql(app, action, blocked_before):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import event
    from haedam_portal.models import db
    with app.app_context():
        if db.engine.dialect.name != "mysql":
            pytest.skip("MySQL snapshot race; exercised by tools/check_mysql.py")
        engine = db.engine
    if blocked_before:
        respond(app, "POST", "/ips/block", {"ip": ATTACKER}, key="mysql-base-0001")
    barrier, local = threading.Barrier(2), threading.local()

    def hold_after_receipt_read(conn, cursor, statement, parameters, context, executemany):
        # Both requests read "no receipt" from their snapshot before either commits.
        if "FROM response_receipts" in statement and not getattr(local, "held", False):
            local.held = True
            barrier.wait(timeout=10)

    def call(_):
        response = respond(app, "POST", f"/ips/{action}", {"ip": ATTACKER}, key=f"mysql-{action}-0001")
        return response.status_code, response.json

    event.listen(engine, "after_cursor_execute", hold_after_receipt_read)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.map(call, range(2))
    finally:
        event.remove(engine, "after_cursor_execute", hold_after_receipt_read)
    assert first == second and first[0] == 200
    assert first[1]["data"]["changed"] is True
