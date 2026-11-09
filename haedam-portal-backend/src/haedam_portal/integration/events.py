import json
import logging
import queue
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g, request

from ..common import client_ip

_lock = threading.Lock()
RULES = {"auth.login_succeeded": "login-success", "auth.login_failed": "login-bruteforce",
         "web.not_found": "web-scan", "web.request": "request-observed", "web.file_access": "file-access"}


def emit(kind, outcome, status, username=None, **details):
    route = request.url_rule.rule if request.url_rule else "unmatched"
    event = {"schema_version": "1.0", "event_id": str(uuid.uuid4()),
             "timestamp": datetime.now(timezone.utc).isoformat(), "source": "haedam-portal",
             "event_type": kind, "username": username,
             "src_ip": client_ip(), "asset_id": current_app.config["ASSET_ID"],
             "outcome": outcome, "details": {"resource": route[:120], "method": request.method if request.method in {"GET","POST","PATCH","DELETE","PUT","HEAD","OPTIONS"} else "OTHER", "status": status, **details}}
    path = current_app.config.get("EVENT_LOG_PATH")
    if path:
        try:
            with _lock:
                target = Path(path)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            logging.getLogger(__name__).warning("Portal event file unavailable")
    if current_app.config.get("GELF_ENABLED"):
        payload = {"version": "1.1", "host": event["asset_id"], "short_message": kind,
                   "level": 6 if outcome == "success" else 4,
                   "_rule": RULES.get(kind, kind), "_event_id": event["event_id"],
                   "_event_type": kind, "_src_ip": event["src_ip"], "_username": username or "anonymous",
                   "_asset_id": event["asset_id"], "_status": status, "_path": route[:120],
                   "_portal_event": json.dumps(event, ensure_ascii=False)}
        payload.update({f"_{name}": details[name] for name in ("file_key", "target_ip") if name in details})
        target = (current_app.config["GELF_HOST"], current_app.config["GELF_PORT"])
        if current_app.config.get("GELF_TRANSPORT") == "tcp":
            _enqueue_tcp(target, json.dumps(payload).encode())
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(0.1)
                    sock.sendto(json.dumps(payload).encode(), target)
            except (OSError, ValueError):
                logging.getLogger(__name__).warning("GELF delivery unavailable")
    return event


# GELF TCP (uncompressed JSON, NUL-terminated frames): the request only enqueues; one daemon thread
# sends, so a slow or unreachable Graylog never delays portal responses (S12 measures response time).
# A failed send keeps the same frame (same event_id and timestamp) and retries until Graylog is back;
# only messages arriving while the queue is full are dropped. The JSONL is written before sending and
# never pruned, so any drop can be found there by event_id.
# ponytail: in-memory queue, messages still queued at process exit are lost; add a spool if that matters.
# A frame that reached Graylog just before the connection broke can be resent, so compare by event_id.
_tcp_queue = queue.Queue(maxsize=1000)
_tcp_started = False
RETRY_DELAYS = (1, 2, 5)  # seconds between attempts, the last one repeats


def _enqueue_tcp(target, data):
    global _tcp_started
    with _lock:
        if not _tcp_started:
            threading.Thread(target=_tcp_sender, name="gelf-tcp", daemon=True).start()
            _tcp_started = True
    try:
        _tcp_queue.put_nowait((target, data))
    except queue.Full:
        logging.getLogger(__name__).warning("GELF queue full, message dropped")


def _tcp_sender():
    sock, connected_to = None, None
    while True:
        target, data = _tcp_queue.get()
        attempt = 0
        while True:
            try:
                if sock is None or connected_to != target:
                    if sock:
                        sock.close()
                    sock, connected_to = socket.create_connection(target, timeout=2), target
                sock.sendall(data + b"\0")
                break
            except OSError:
                if sock:
                    sock.close()
                sock = None
                if attempt:  # the first failure is usually a connection Graylog closed while idle
                    if attempt == 1:
                        logging.getLogger(__name__).warning("GELF delivery unavailable, retrying")
                    time.sleep(RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)])
                attempt += 1
