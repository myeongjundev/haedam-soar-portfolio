import os
import re
import secrets
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from flask_migrate import Migrate
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from .common import ApiError, client_ip, fail, file_key, ok
from .models import db

ROOT = Path(__file__).resolve().parents[2]


def create_app(config=None):
    app = Flask(__name__, static_folder=None, instance_path=str(ROOT / "instance"))
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    dist = os.environ.get("FRONTEND_DIST", str(ROOT.parent / "haedam-portal-frontend" / "dist"))
    app.config.update(
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///haedam.sqlite3"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False, SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        FRONTEND_DIST=str(Path(dist).resolve()), MAX_CONTENT_LENGTH=32 * 1024,
        COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1", SESSION_TTL=14400, LOGIN_RATE_LIMIT=20,
        DUMMY_PASSWORD_HASH=generate_password_hash(secrets.token_urlsafe(24)),
        EVENT_LOG_PATH=os.environ.get("EVENT_LOG_PATH", str(ROOT / "instance" / "events.jsonl")),
        ASSET_ID=os.environ.get("ASSET_ID", "haedam-portal"),
        GELF_ENABLED=os.environ.get("GELF_ENABLED", "0") == "1", GELF_HOST=os.environ.get("GELF_HOST", "127.0.0.1"),
        GELF_PORT=int(os.environ.get("GELF_PORT", "12201")), GELF_TRANSPORT=os.environ.get("GELF_TRANSPORT", "udp"),
        RESPONSE_API_KEY=os.environ.get("RESPONSE_API_KEY", ""),
        RESPONSE_ALLOWED_CIDRS=[x.strip() for x in os.environ.get("RESPONSE_ALLOWED_CIDRS", "").split(",") if x.strip()],
        DASHBOARD_URL=os.environ.get("DASHBOARD_URL", ""),
    )
    if config:
        app.config.update(config)
    db.init_app(app)
    Migrate(app, db, directory=str(ROOT / "migrations"))
    from .auth import bp as auth_bp, load_session
    from .petitions import bp as petitions_bp, CATEGORIES
    from .admin import bp as admin_bp
    from .integration import bp as response_bp, ip_blocked
    from .integration.events import emit
    from .cli import register_cli
    for bp in (auth_bp, petitions_bp, admin_bp, response_bp):
        app.register_blueprint(bp)
    register_cli(app)

    @app.before_request
    def authenticate():
        g.user, g.login_session, g.new_cookie = None, None, None
        if ip_blocked(client_ip()):
            g.ip_blocked = True
            fail(403, "IP_BLOCKED", "접근이 차단된 주소입니다.")
        if not request.path.startswith("/api/v1/") or request.path == "/api/v1/health":
            return
        if request.path.startswith("/api/v1/response/"):
            return
        load_session()
        if request.method in {"POST", "PATCH", "DELETE", "PUT"}:
            if not request.is_json:
                fail(400, "VALIDATION_ERROR", "JSON 형식으로 요청해 주세요.")
            origin = request.headers.get("Origin")
            if origin and origin != request.host_url.rstrip("/"):
                fail(403, "CSRF_FAILED", "다른 사이트에서 보낸 요청은 허용하지 않습니다.")
            supplied = request.headers.get("X-CSRF-Token", "")
            if not g.login_session or not secrets.compare_digest(supplied, g.login_session.csrf):
                fail(403, "CSRF_FAILED", "보안 세션이 만료됐습니다. 새로고침 후 다시 시도해 주세요.")

    @app.after_request
    def finish(response):
        if getattr(g, "new_cookie", None):
            response.set_cookie("haedam_session", g.new_cookie, httponly=True, secure=app.config["COOKIE_SECURE"],
                                samesite="Lax", max_age=app.config["SESSION_TTL"], path="/")
        if getattr(g, "clear_cookie", False):
            response.delete_cookie("haedam_session", path="/", httponly=True, samesite="Lax", secure=app.config["COOKIE_SECURE"])
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store" if not request.path.startswith("/assets/") else "public, max-age=3600"
        if response.status_code == 404:
            emit("web.not_found", "failure", 404)
        if not request.path.startswith("/assets/") and request.path != "/favicon.svg":
            outcome = "denied" if g.get("ip_blocked") else "success" if response.status_code < 400 else "failure"
            emit("web.request", outcome, response.status_code)
        # S7 joins FIM alerts to the served file by its web-root key; never the query string.
        if g.get("file_key") and response.status_code < 400:
            emit("web.file_access", "success", response.status_code, file_key=g.file_key)
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        db.session.rollback()
        code = getattr(error, "error_code", None) or {404: "NOT_FOUND", 413: "TOO_LARGE", 405: "METHOD_NOT_ALLOWED"}.get(error.code, "REQUEST_ERROR")
        message = error.description if isinstance(error, ApiError) else {404: "페이지 또는 자료를 찾을 수 없습니다.", 413: "요청 크기가 너무 큽니다.", 405: "허용되지 않는 요청 방식입니다."}.get(error.code, "요청을 확인해 주세요.")
        payload = {"code": code, "message": message}
        if isinstance(error, ApiError) and error.fields:
            payload["fields"] = error.fields
        return jsonify(success=False, error=payload), error.code

    @app.errorhandler(IntegrityError)
    def conflict(error):
        db.session.rollback()
        return jsonify(success=False, error={"code": "CONFLICT", "message": "이미 처리되거나 변경된 요청입니다. 새로고침해 주세요."}), 409

    @app.errorhandler(SQLAlchemyError)
    def database_unavailable(error):
        db.session.rollback()
        app.logger.warning("Database operation failed; sensitive exception omitted")
        return jsonify(success=False, error={"code": "NOT_READY", "message": "저장소에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요."}), 503

    @app.errorhandler(Exception)
    def unexpected(error):
        db.session.rollback()
        app.logger.error("Unexpected application failure; sensitive exception omitted")
        return jsonify(success=False, error={"code": "INTERNAL_ERROR", "message": "처리 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."}), 500

    @app.get("/api/v1/health")
    def health():
        # Include the actual business table in readiness, not just DB reachability.
        db.session.execute(text("SELECT id FROM petitions LIMIT 1"))
        return ok({"service": "haedam-portal", "status": "ok"})

    @app.get("/api/v1/config")
    def public_config():
        url = app.config["DASHBOARD_URL"]
        return ok({"categories": CATEGORIES, "departments": ["민원행정과"],
                   "dashboard_url": url if g.user and g.user.role == "admin" and re.match(r"^https?://", url) else None})

    @app.get("/assets/<path:filename>")
    def assets(filename):
        g.file_key = file_key("assets/" + filename)
        if not g.file_key:
            fail(404, "NOT_FOUND", "페이지 또는 자료를 찾을 수 없습니다.")
        return send_from_directory(Path(app.config["FRONTEND_DIST"]) / "assets", filename)

    @app.get("/favicon.svg")
    def favicon():
        g.file_key = "favicon.svg"
        return send_from_directory(app.config["FRONTEND_DIST"], "favicon.svg")

    def frontend():
        if not (Path(app.config["FRONTEND_DIST"]) / "index.html").is_file():
            fail(503, "NOT_READY", "프론트 빌드 결과가 없습니다. npm run build를 먼저 실행해 주세요.")
        g.file_key = "index.html"
        return send_from_directory(app.config["FRONTEND_DIST"], "index.html")

    for index, path in enumerate(["/", "/login", "/register", "/petitions", "/petitions/new", "/petitions/<int:petition_id>", "/work", "/admin", "/account"]):
        app.add_url_rule(path, f"frontend_{index}", lambda **kwargs: frontend(), methods=["GET"])
    return app
