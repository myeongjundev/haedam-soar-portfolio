import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import select

from conftest import Actor
from haedam_portal.models import User, db


def check_response(response):
    assert response.status_code == 200, response.json
    schema = json.loads((Path(__file__).resolve().parents[1] / "contracts/portal-admin-users.schema.json")
                        .read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(response.json)
    return response.json["data"]


def test_search_wide_summary_and_intersection_across_all_pages(app, actors):
    with app.app_context():
        hashed = db.session.scalar(select(User.password_hash).limit(1))
        rows = [User(username=f"scope_{i:02}", display_name=f"가상계정{i:02}", password_hash=hashed,
                     role=("citizen", "staff", "admin")[i % 3], locked=i % 4 == 0) for i in range(27)]
        db.session.add_all(rows)
        db.session.commit()
        expected = [u.public() for u in rows]
    admin = actors["admin"]
    for role in ("", "citizen", "staff", "admin"):
        for locked in ("", "true", "false"):
            subset = [u for u in expected if (not role or u["role"] == role)
                      and (not locked or u["locked"] == (locked == "true"))]
            params = {"q": "scope_", "role": role, "locked": locked, "page_size": 4}
            first = check_response(admin.call("GET", "/admin/users", query_string=params))
            assert first["total"] == len(subset)
            assert first["pages"] == max(1, (len(subset) + 3) // 4)
            summary = first["summary"]
            assert summary == {"scope": "search", "total": 27,
                               "roles": {"citizen": 9, "staff": 9, "admin": 9}, "locked": 7, "unlocked": 20}
            collected = first["items"]
            for page in range(2, first["pages"] + 1):
                result = check_response(admin.call("GET", "/admin/users", query_string={**params, "page": page}))
                assert result["summary"] == summary
                assert result["total"] == len(subset)
                collected += result["items"]
            assert collected == subset
    # Querying beyond the last page does not turn a nonempty result into zero total.
    outside = check_response(admin.call("GET", "/admin/users?q=scope_&page=100"))
    assert outside["items"] == [] and outside["total"] == 27 and outside["summary"]["total"] == 27
    empty = check_response(admin.call("GET", "/admin/users?q=no_such_synthetic_user"))
    assert empty["items"] == [] and empty["total"] == 0 and empty["pages"] == 1
    assert empty["summary"]["total"] == empty["summary"]["locked"] == empty["summary"]["unlocked"] == 0


def test_search_treats_sql_wildcards_literally_and_updates_after_role_lock_reset(app, actors):
    with app.app_context():
        target = User(username="literal_case", display_name="기호%_이름", role="citizen",
                      password_hash=db.session.scalar(select(User.password_hash).limit(1)))
        db.session.add(target)
        db.session.commit()
        target_id = target.id
    admin = actors["admin"]
    for q in ("%", "_이름", "  기호%_이름  "):
        result = check_response(admin.call("GET", "/admin/users", query_string={"q": q}))
        assert [u["id"] for u in result["items"]] == [target_id]
        assert result["summary"]["total"] == 1
    assert admin.call("PATCH", f"/admin/users/{target_id}", {"role": "staff"}).status_code == 200
    assert admin.call("PATCH", f"/admin/users/{target_id}", {"locked": True}).status_code == 200
    result = check_response(admin.call("GET", "/admin/users?q=literal_case&role=citizen"))
    assert result["items"] == [] and result["total"] == 0
    assert result["summary"] == {"scope": "search", "total": 1,
                                "roles": {"citizen": 0, "staff": 1, "admin": 0}, "locked": 1, "unlocked": 0}
    assert admin.call("POST", f"/admin/users/{target_id}/reset-password",
                      {"new_password": "Synthetic-reset-password-123"}).status_code == 200
    result = check_response(admin.call("GET", "/admin/users?q=literal_case&locked=false"))
    assert result["total"] == 1 and result["summary"]["unlocked"] == 1


@pytest.mark.parametrize("query", ["role=root", "role=STAFF", "locked=1", "locked=True", "locked=no",
                                  "role=staff&role=citizen", "locked=true&locked=false",
                                  "page=0", "page_size=51", "page_size=x"])
def test_admin_listing_rejects_ambiguous_or_invalid_filters(actors, query):
    response = actors["admin"].call("GET", "/admin/users?" + query)
    assert response.status_code == 400
    assert response.json["error"]["code"] == "VALIDATION_ERROR"
    assert "summary" not in response.json


def test_summary_is_not_disclosed_to_non_administrators(app, actors):
    for actor, expected_status in [(Actor(app), 401), (actors["citizen"], 403), (actors["staff"], 403)]:
        response = actor.call("GET", "/admin/users?role=admin&locked=false")
        assert response.status_code == expected_status
        assert "summary" not in response.json and "items" not in response.json
