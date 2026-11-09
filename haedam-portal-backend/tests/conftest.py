import os
import pytest
from werkzeug.security import generate_password_hash
from sqlalchemy.engine import make_url

from haedam_portal import create_app
from haedam_portal.models import User, db

PASSWORD = "Synthetic-test-password-123"


@pytest.fixture
def app(tmp_path):
    external = os.environ.get("HAEDAM_TEST_DATABASE_URL")
    if external and (os.environ.get("HAEDAM_TEST_ALLOW_DISPOSABLE") != "1" or make_url(external).database != "haedam_qa"):
        raise RuntimeError("Refusing to reset a database outside the disposable MySQL QA tool")
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": os.environ.get("HAEDAM_TEST_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.sqlite3').as_posix()}"),
                      "EVENT_LOG_PATH": str(tmp_path / "events.jsonl"), "GELF_ENABLED": False,
                      "LOGIN_RATE_LIMIT": 100, "RESPONSE_API_KEY": "test-only-response-key-123456789",
                      "RESPONSE_ALLOWED_CIDRS": ["127.0.0.0/8"], "FRONTEND_DIST": str(tmp_path / "dist")})
    with app.app_context():
        if os.environ.get("HAEDAM_TEST_DATABASE_URL"):
            # Only tools/check_mysql.py sets this to its disposable container's database.
            db.drop_all()
        db.create_all()
        hashed = generate_password_hash(PASSWORD)
        db.session.add_all([User(username=name, display_name=display, password_hash=hashed, role=role)
                            for name, display, role in [("citizen", "시민하나", "citizen"), ("other", "시민둘", "citizen"),
                                                        ("staff", "담당하나", "staff"), ("staff2", "담당둘", "staff"), ("admin", "관리하나", "admin")]])
        db.session.commit()
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


class Actor:
    def __init__(self, app, username=None):
        self.client = app.test_client()
        self.csrf = self.client.get("/api/v1/auth/me").json["data"]["csrf_token"]
        if username:
            response = self.call("POST", "/auth/login", {"username": username, "password": PASSWORD})
            assert response.status_code == 200, response.json
            self.csrf = response.json["data"]["csrf_token"]

    def call(self, method, path, data=None, **kwargs):
        return self.client.open("/api/v1" + path, method=method, json=data,
                                headers={"X-CSRF-Token": self.csrf}, **kwargs)


@pytest.fixture
def actors(app):
    return {name: Actor(app, name) for name in ["citizen", "other", "staff", "staff2", "admin"]}
