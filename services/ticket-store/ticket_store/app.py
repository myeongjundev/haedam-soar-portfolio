"""Two Flask apps on two ports (design section 4).

- n8n app (container 8088, published on 192.0.2.3): check/record only, key required.
- dashboard app (container 8089, published on 127.0.0.1): read API and screens, no key.
Splitting by port keeps the dashboard off the VPN even though Docker Desktop may
hide the real source address.
"""
from flask import Flask, jsonify

from . import api_n8n, api_read, dashboard, db


def _base_app(db_path):
    app = Flask(__name__)
    app.config["TICKET_STORE_DB"] = db_path
    app.extensions["ticket_store_conn"] = lambda: db.connect(app.config["TICKET_STORE_DB"])
    db.connect(db_path).close()

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(ok=False, error={"code": "NOT_FOUND", "message": "path not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify(ok=False, error={"code": "NOT_FOUND", "message": "method not allowed"}), 405

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(ok=False, error={"code": "VALIDATION_ERROR", "message": "body is larger than 64 KB"}), 413

    @app.errorhandler(500)
    def server_error(_):
        # n8n retries 500/503 with the same Idempotency-Key, so this must stay in the agreed JSON shape.
        return jsonify(ok=False, error={"code": "SERVER_ERROR", "message": "ticket store error"}), 500

    return app


def create_n8n_app(db_path, key):
    """check/record for the D n8n result-log."""
    if not key or len(key) < 16:
        raise ValueError("TICKET_STORE_KEY must be set (16+ characters)")
    app = _base_app(db_path)
    app.config["TICKET_STORE_KEY"] = key
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.register_blueprint(api_n8n.bp)
    return app


def create_dashboard_app(db_path, origin="http://127.0.0.1:8089"):
    app = _base_app(db_path)
    app.config["DASHBOARD_ORIGIN"] = origin
    app.register_blueprint(api_read.bp)
    app.register_blueprint(dashboard.bp)
    return app
