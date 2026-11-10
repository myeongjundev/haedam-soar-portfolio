"""Run both apps: python -m ticket_store (container entry point)."""
import os
import threading

from werkzeug.serving import make_server

from . import db, samples
from .app import create_dashboard_app, create_n8n_app


def main():
    db_path = os.environ.get("TICKET_STORE_DB", "/data/tickets.db")
    if os.environ.get("TICKET_STORE_SAMPLES") == "1":
        conn = db.connect(db_path)
        print(f"samples added: {samples.load_samples(conn)}", flush=True)
        conn.close()
    n8n_app = create_n8n_app(db_path, os.environ.get("TICKET_STORE_KEY", ""))
    dashboard_app = create_dashboard_app(db_path, os.environ.get("DASHBOARD_ORIGIN", "http://127.0.0.1:8089"))
    servers = [make_server("0.0.0.0", 8088, n8n_app, threaded=True),
               make_server("0.0.0.0", 8089, dashboard_app, threaded=True)]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    print("ticket store: n8n 8088, dashboard 8089", flush=True)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
