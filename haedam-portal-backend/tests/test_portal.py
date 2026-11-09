import json
from datetime import timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import select

from conftest import Actor, PASSWORD
from haedam_portal import create_app
from haedam_portal.models import LoginSession, Petition, ResponseReceipt, User, db, now

PETITION = {"title": "가상 해담로 가로등 점검 요청", "content": "가상 해담로의 가로등이 켜지지 않아 보행이 불편합니다. 점검을 요청합니다.", "category": "안전·시설"}


def create(actor):
    response = actor.call("POST", "/petitions", PETITION)
    assert response.status_code == 201
    return response.json["data"]


def test_complete_workflow_and_private_data(actors):
    citizen, staff = actors["citizen"], actors["staff"]
    data = create(citizen)
    pid = data["id"]
    assert actors["other"].call("GET", f"/petitions/{pid}").status_code == 404
    assert actors["other"].call("GET", "/petitions?q=가로등").json["data"]["total"] == 0
    assert actors["admin"].call("GET", f"/petitions/{pid}").status_code == 403
    assert staff.call("PATCH", f"/petitions/{pid}/status", {"status":"in_progress","version":1}).status_code == 403
    data = staff.call("PATCH", f"/petitions/{pid}/assignment", {}).json["data"]
    assert actors["staff2"].call("GET", f"/petitions/{pid}").status_code == 404
    data = staff.call("PATCH", f"/petitions/{pid}/status", {"status":"in_progress","version":data["version"]}).json["data"]
    reply = "가로등 점검과 수리를 완료했습니다. 안전한 보행을 위해 의견을 주셔서 감사합니다."
    data = staff.call("PATCH", f"/petitions/{pid}/status", {"status":"completed","reply":reply,"version":data["version"]}).json["data"]
    final = citizen.call("GET", f"/petitions/{pid}").json["data"]
    assert final["status"] == "completed" and final["reply"] == reply
    assert len(final["history"]) == 4


def test_stale_version_and_invalid_transition(actors):
    data = create(actors["citizen"])
    staff = actors["staff"]
    pid = data["id"]
    data = staff.call("PATCH", f"/petitions/{pid}/assignment", {}).json["data"]
    assert staff.call("PATCH", f"/petitions/{pid}/status", {"status":"completed","version":data["version"],"reply":"완료 답변을 충분히 작성했습니다."}).status_code == 409
    assert staff.call("PATCH", f"/petitions/{pid}/status", {"status":"in_progress","version":data["version"]-1}).status_code == 409
    assert actors["citizen"].call("PATCH", f"/petitions/{pid}/assignment", {}).status_code == 403


@pytest.mark.parametrize("change", [{"title":"짧음"}, {"content":"짧음"}, {"category":"unknown"}, {"title":123}, {"content":"x"*5001}])
def test_invalid_petition(actors, change):
    assert actors["citizen"].call("POST", "/petitions", {**PETITION, **change}).status_code == 400


@pytest.mark.parametrize("query", ["page=0", "page=no", "page_size=1000", "status=bad", "category=bad"])
def test_invalid_list_query(actors, query):
    assert actors["citizen"].call("GET", "/petitions?" + query).status_code == 400


def test_csrf_cookie_and_session_rotation(app):
    anon = Actor(app)
    old_cookie = anon.client.get_cookie("haedam_session").value
    assert anon.client.post("/api/v1/auth/login", json={"username":"citizen","password":PASSWORD}).status_code == 403
    response = anon.client.post("/api/v1/auth/login", json={"username":"citizen","password":PASSWORD}, headers={"X-CSRF-Token":anon.csrf,"Origin":"https://evil.example"})
    assert response.status_code == 403
    response = anon.call("POST", "/auth/login", {"username":"citizen","password":PASSWORD})
    assert response.status_code == 200
    assert anon.client.get_cookie("haedam_session").value != old_cookie
    assert "HttpOnly" in response.headers["Set-Cookie"] and "SameSite=Lax" in response.headers["Set-Cookie"]
    assert "access_token" not in response.json["data"]
    stolen = app.test_client()
    stolen.set_cookie("haedam_session", old_cookie)
    assert stolen.get("/api/v1/petitions").status_code == 401


def test_logout_revokes_cookie_replay(app):
    actor = Actor(app,"citizen")
    old = actor.client.get_cookie("haedam_session").value
    assert actor.call("POST", "/auth/logout", {}).status_code == 200
    actor.client.set_cookie("haedam_session", old)
    assert actor.call("GET", "/petitions").status_code == 401


def test_session_expiry(app):
    actor = Actor(app,"citizen")
    with app.app_context():
        for session in db.session.scalars(select(LoginSession).where(LoginSession.user_id == 1)):
            session.expires_at = now() - timedelta(seconds=1)
        db.session.commit()
    assert actor.call("GET", "/petitions").status_code == 401


def test_password_change_revokes_other_devices(app):
    first, second = Actor(app,"citizen"), Actor(app,"citizen")
    response = first.call("POST", "/auth/password", {"current_password":PASSWORD,"new_password":"New-test-password-123"})
    assert response.status_code == 200
    assert first.call("GET", "/petitions").status_code == 200
    assert second.call("GET", "/petitions").status_code == 401
    anon = Actor(app)
    assert anon.call("POST", "/auth/login", {"username":"citizen","password":PASSWORD}).status_code == 401


def test_admin_lock_reset_and_role_change_revoke_sessions(app, actors):
    admin, citizen = actors["admin"], actors["citizen"]
    assert admin.call("PATCH", "/admin/users/1", {"locked":True}).status_code == 200
    assert citizen.call("GET", "/petitions").status_code == 401
    anon = Actor(app)
    assert anon.call("POST", "/auth/login", {"username":"citizen","password":PASSWORD}).status_code == 401
    assert admin.call("PATCH", "/admin/users/1", {"locked":False}).status_code == 400
    assert admin.call("POST", "/admin/users/1/reset-password", {"new_password":"Reset-test-password-123"}).status_code == 200
    assert citizen.call("GET", "/petitions").status_code == 401
    result = anon.call("POST", "/auth/login", {"username":"citizen","password":"Reset-test-password-123"})
    assert result.status_code == 200
    assert admin.call("PATCH", "/admin/users/1", {"role":"staff"}).status_code == 200
    assert anon.call("GET", "/petitions").status_code == 401
    assert admin.call("PATCH", "/admin/users/5", {"role":"citizen"}).status_code == 409


def test_admin_unlock_keeps_password_without_restoring_sessions(app, actors):
    admin, citizen = actors["admin"], actors["citizen"]
    assert admin.call("PATCH", "/admin/users/1", {"locked": True}).status_code == 200
    assert citizen.call("GET", "/petitions").status_code == 401  # 잠금으로 세션 회수
    bad = admin.call("POST", "/admin/users/1/unlock", {"reason_code": "other"})
    assert bad.status_code == 400  # 사유 코드는 false_positive만 허용
    result = admin.call("POST", "/admin/users/1/unlock", {"reason_code": "false_positive"})
    assert result.status_code == 200 and result.json["data"]["locked"] is False
    assert citizen.call("GET", "/petitions").status_code == 401  # 기존 세션은 복원되지 않음
    anon = Actor(app)
    assert anon.call("POST", "/auth/login", {"username": "citizen", "password": PASSWORD}).status_code == 200  # 비밀번호 유지
    assert admin.call("POST", "/admin/users/5/unlock", {"reason_code": "false_positive"}).status_code == 409  # 본인 계정 제외
    events = [json.loads(line) for line in Path(app.config["EVENT_LOG_PATH"]).read_text(encoding="utf-8").splitlines()]
    unlocked = [e for e in events if e["event_type"] == "auth.account_unlocked"]
    assert len(unlocked) == 1  # 실제 잠금→해제 1건만, 사유 코드 오류나 본인 시도는 기록 안 함
    assert unlocked[0]["username"] == "citizen"
    assert unlocked[0]["details"]["actor_user_id"] == 5 and unlocked[0]["details"]["actor_username"] == "admin"
    assert unlocked[0]["details"]["reason_code"] == "false_positive"


def test_admin_unlock_on_unlocked_account_keeps_sessions(app, actors):
    admin, citizen = actors["admin"], actors["citizen"]
    assert citizen.call("GET", "/petitions").status_code == 200
    result = admin.call("POST", "/admin/users/1/unlock", {"reason_code": "false_positive"})
    assert result.status_code == 200 and result.json["data"]["locked"] is False
    assert citizen.call("GET", "/petitions").status_code == 200  # 잠기지 않은 계정의 정상 세션은 끊지 않는다
    events = [json.loads(line) for line in Path(app.config["EVENT_LOG_PATH"]).read_text(encoding="utf-8").splitlines()]
    assert not [e for e in events if e["event_type"] == "auth.account_unlocked"]


def test_registration_never_elevates_privilege(app):
    anon = Actor(app)
    response = anon.call("POST", "/auth/register", {"username":"new_test","display_name":"가상시민","password":PASSWORD,"role":"admin"})
    assert response.status_code == 201 and response.json["data"]["role"] == "citizen"
    assert anon.call("POST", "/auth/register", {"username":"new_test","display_name":"가상시민","password":PASSWORD}).status_code == 409


def test_role_access_and_admin_account_creation(actors):
    assert actors["citizen"].call("GET", "/admin/users").status_code == 403
    response = actors["admin"].call("POST", "/admin/users", {"username":"new_staff","display_name":"신규담당","password":PASSWORD,"role":"staff"})
    assert response.status_code == 201
    assert "password" not in json.dumps(response.json)
    assert actors["staff"].call("POST", "/petitions", PETITION).status_code == 403


def test_persistence_after_app_restart(app, actors):
    data = create(actors["citizen"])
    clone = create_app(dict(app.config))
    actor = Actor(clone,"citizen")
    assert actor.call("GET", f"/petitions/{data['id']}").json["data"]["content"] == PETITION["content"]
    with clone.app_context():
        db.session.remove()
        db.engine.dispose()


def test_events_schema_privacy_ip_and_404(app, actors):
    create(actors["citizen"])
    client = app.test_client()
    assert client.get("/not-a-real-route?private=do-not-log", headers={"X-Forwarded-For":"203.0.113.42"}).status_code == 404
    events = [json.loads(line) for line in Path(app.config["EVENT_LOG_PATH"]).read_text(encoding="utf-8").splitlines()]
    schema = json.loads((Path(__file__).resolve().parents[1] / "contracts/portal-event.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for event in events:
        validator.validate(event)
    scan = next(e for e in events if e["event_type"] == "web.not_found")
    assert scan["src_ip"] == "127.0.0.1" and scan["details"]["resource"] == "unmatched"
    raw = json.dumps(events,ensure_ascii=False)
    assert PETITION["content"] not in raw and PETITION["title"] not in raw
    assert PASSWORD not in raw and "do-not-log" not in raw and "haedam_session" not in raw


def test_response_auth_idempotency_lock_and_reset(app, actors):
    client = app.test_client()
    path = "/api/v1/response/accounts/1/lock"
    headers = {"X-Response-Key":app.config["RESPONSE_API_KEY"],"Idempotency-Key":"test-lock-0001"}
    assert client.post(path,json={}).status_code == 403
    assert client.post(path,json={},headers=headers,environ_overrides={"REMOTE_ADDR":"192.0.2.1"}).status_code == 403
    result = client.post(path,json={},headers=headers)
    assert result.status_code == 200 and result.json["data"]["locked"]
    assert actors["citizen"].call("GET", "/petitions").status_code == 401
    replay = client.post(path,json={},headers=headers)
    assert replay.json == result.json
    assert client.post(path,json={"different":True},headers=headers).status_code == 409
    assert client.post("/api/v1/response/accounts/5/lock",json={},headers={**headers,"Idempotency-Key":"test-admin-0001"}).status_code == 403
    reset = client.post("/api/v1/response/accounts/1/reset",json={"new_password":"Response-new-password-123"},headers={**headers,"Idempotency-Key":"test-reset-0001"})
    assert reset.status_code == 200 and not reset.json["data"]["locked"]
    assert actors["citizen"].call("GET", "/petitions").status_code == 401
    with app.app_context():
        for receipt in db.session.scalars(select(ResponseReceipt)):
            assert "password" not in json.dumps(receipt.result)


def test_response_locks_by_username_from_s4_events(app, actors):
    client = app.test_client()
    path = "/api/v1/response/accounts/lock"
    headers = {"X-Response-Key":app.config["RESPONSE_API_KEY"],"Idempotency-Key":"T-111-citizen-lock"}
    assert client.post(path,json={"username":"citizen"},headers={"Idempotency-Key":"T-111-citizen-lock"}).status_code == 403
    assert client.post(path,json={"username":"citizen"},headers=headers,environ_overrides={"REMOTE_ADDR":"192.0.2.1"}).status_code == 403
    # Normalized like login, so the lock hits the account the S4 event names.
    result = client.post(path,json={"username":" Citizen "},headers=headers)
    assert result.status_code == 200
    assert result.json["data"] == {"user_id":1,"locked":True,"changed":True,"revoked_sessions":1}
    assert actors["citizen"].call("GET", "/petitions").status_code == 401
    assert client.post(path,json={"username":" Citizen "},headers=headers).json == result.json
    assert client.post(path,json={"username":"other"},headers=headers).status_code == 409
    again = client.post(path,json={"username":"citizen"},headers={**headers,"Idempotency-Key":"T-111-citizen-lock-2"})
    assert again.json["data"] == {"user_id":1,"locked":True,"changed":False,"revoked_sessions":0}
    assert client.post(path,json={"username":"admin"},headers={**headers,"Idempotency-Key":"T-111-admin-lock"}).status_code == 403
    assert client.post(path,json={"username":"nobody"},headers={**headers,"Idempotency-Key":"T-111-nobody-lock"}).status_code == 404
    for bad in [{}, {"username":7}, {"username":" "}]:
        assert client.post(path,json=bad,headers={**headers,"Idempotency-Key":"T-111-bad-input"}).status_code == 400
    # Unlocking stays a person's reset by id; there is no reset by username.
    reset = client.post("/api/v1/response/accounts/reset",json={"username":"citizen","new_password":"Response-new-password-123"},
                        headers={**headers,"Idempotency-Key":"T-111-citizen-reset"})
    assert reset.status_code == 404
    events = [json.loads(line) for line in Path(app.config["EVENT_LOG_PATH"]).read_text(encoding="utf-8").splitlines()]
    locked = [e["username"] for e in events if e["event_type"] == "auth.account_locked"]
    assert locked and set(locked) == {"citizen"}


def test_login_rate_limit_and_health(app):
    app.config["LOGIN_RATE_LIMIT"] = 2
    actor=Actor(app)
    for _ in range(2):
        assert actor.call("POST", "/auth/login", {"username":"citizen","password":"wrong"}).status_code == 401
    assert actor.call("POST", "/auth/login", {"username":"citizen","password":PASSWORD}).status_code == 429
    assert actor.call("GET", "/health").json["data"]["status"] == "ok"


def test_missing_frontend_and_real_404(app):
    client=app.test_client()
    assert client.get("/").status_code == 503
    assert client.get("/random-route").status_code == 404
    assert client.get("/assets/does-not-exist.js").status_code == 404


def test_body_size_and_security_headers(app, actors):
    response = actors["citizen"].call("POST", "/petitions", {**PETITION,"content":"a"*40000})
    assert response.status_code == 413
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize("path,body", [("/api/v1/response/accounts/1/lock", {}), ("/api/v1/response/accounts/lock", {"username":"citizen"})])
def test_concurrent_mysql_response_replays_one_committed_effect(app, actors, path, body):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    with app.app_context():
        if db.engine.dialect.name != "mysql":
            pytest.skip("MySQL row-lock test; exercised by tools/check_mysql.py")
    barrier = Barrier(2)
    def call():
        with app.test_client() as client:
            barrier.wait(timeout=10)
            response = client.post(path, json=body, headers={
                "X-Response-Key":app.config["RESPONSE_API_KEY"], "Idempotency-Key":"concurrent-lock-0001"})
            return response.status_code, response.json
    with ThreadPoolExecutor(max_workers=2) as pool:
        a,b=list(pool.map(lambda _:call(),range(2)))
    assert a[0] == b[0] == 200
    assert a[1] == b[1]
    assert a[1]["data"]["revoked_sessions"] == 1


def test_validation_errors_are_localized_and_match_field_contract(actors):
    schema = json.loads((Path(__file__).resolve().parents[1] / "contracts/portal-error.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for field, value, message in [("title", "짧음", "제목은 5~120자로 입력해 주세요."),
                                  ("content", "짧음", "민원 내용은 10~5000자로 입력해 주세요."),
                                  ("category", "unapproved", "민원 분야를 선택해 주세요.")]:
        response = actors["citizen"].call("POST", "/petitions", {**PETITION, field:value})
        assert response.status_code == 400
        validator.validate(response.json)
        assert response.json["error"]["fields"] == {field:message}
        assert response.json["error"]["message"] == message
        assert value not in response.json["error"]["message"]


def test_reply_validation_does_not_complete_petition_or_echo_content(actors):
    data = create(actors["citizen"])
    staff=actors["staff"]
    data=staff.call("PATCH", f"/petitions/{data['id']}/assignment", {}).json["data"]
    data=staff.call("PATCH", f"/petitions/{data['id']}/status", {"status":"in_progress","version":data["version"]}).json["data"]
    result=staff.call("PATCH", f"/petitions/{data['id']}/status", {"status":"completed","reply":"짧음","version":data["version"]})
    assert result.status_code==400
    assert result.json["error"]["fields"]=={"reply":"처리 결과 답변은 10~3000자로 입력해 주세요."}
    assert staff.call("GET", f"/petitions/{data['id']}").json["data"]["status"]=="in_progress"
