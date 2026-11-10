"""Disposable database and synthetic accounts, only for automated browser tests."""
import os
import json
import tempfile
from pathlib import Path

from flask_migrate import upgrade
from waitress import serve
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from sqlalchemy.engine import make_url

from haedam_portal import create_app
from haedam_portal.models import User, db

with tempfile.TemporaryDirectory(prefix="haedam-e2e-", dir=os.environ.get("HAEDAM_E2E_RUNTIME_ROOT")) as directory:
    external = os.environ.get("HAEDAM_E2E_DATABASE_URL")
    if external:
        target = make_url(external)
        if (os.environ.get("HAEDAM_E2E_ALLOW_DISPOSABLE") != "1"
                or target.drivername != "mysql+pymysql" or target.host != "127.0.0.1"
                or target.database != "haedam_e2e" or target.username != "haedam_e2e"):
            raise RuntimeError("Refusing a database outside the disposable MySQL browser runner")
    app = create_app({"SQLALCHEMY_DATABASE_URI": external or "sqlite:///" + (Path(directory)/"e2e.sqlite3").as_posix(),
                      "EVENT_LOG_PATH": str(Path(directory)/"events.jsonl"), "GELF_ENABLED":False, "LOGIN_RATE_LIMIT":1000,
                      "COOKIE_SECURE":False, "RESPONSE_API_KEY":"", "RESPONSE_ALLOWED_CIDRS":[]})
    with app.app_context():
        upgrade()
        # Restart uses the same database and accounts; it never resets test data.
        if db.session.query(User).count() == 0:
            for username, display, role in [("citizen_e2e","테스트시민","citizen"),("staff_e2e","테스트담당","staff"),("admin_e2e","테스트관리","admin")]:
                db.session.add(User(username=username,display_name=display,role=role,password_hash=generate_password_hash("E2E-only-password-123")))
            db.session.commit()
        if external:
            assert db.engine.dialect.name == "mysql"
            database, version = db.session.execute(text("SELECT DATABASE(), VERSION()")).one()
            Path(os.environ["HAEDAM_E2E_READY_FILE"]).write_text(json.dumps({
                "pid":os.getpid(), "parent_pid":os.getppid(), "dialect":db.engine.dialect.name,
                "database":database, "version":version,
            }), encoding="utf-8")
    print("Haedam E2E ready http://127.0.0.1:5005",flush=True)
    try:
        serve(app,host="127.0.0.1",port=5005)
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
