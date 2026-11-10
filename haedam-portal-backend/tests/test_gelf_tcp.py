import json
import socket
import time

from test_ip_block_and_file_key import NORMAL, events, frontend, visit


def test_gelf_tcp_frames_match_the_local_event_log(app):
    frontend(app)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(3)
    app.config.update(GELF_ENABLED=True, GELF_TRANSPORT="tcp", GELF_HOST="127.0.0.1", GELF_PORT=server.getsockname()[1])
    try:
        for path in ("/login", "/no-such-page"):
            visit(app, path, NORMAL)
        conn, _ = server.accept()
        conn.settimeout(2)
        expected = {e["event_id"] for e in events(app)}
        data = b""
        while data.count(b"\0") < len(expected):
            data += conn.recv(65535)
        conn.close()
    finally:
        server.close()
    frames = [json.loads(f) for f in data.split(b"\0") if f]
    assert {m["_event_id"] for m in frames} == expected
    assert {m["_rule"] for m in frames} >= {"request-observed", "file-access", "web-scan"}


def test_gelf_tcp_resends_the_same_frames_after_graylog_recovers(app, monkeypatch):
    from haedam_portal.integration import events as portal_events

    monkeypatch.setattr(portal_events, "RETRY_DELAYS", (0.05,))
    frontend(app)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens yet: Graylog is down
    app.config.update(GELF_ENABLED=True, GELF_TRANSPORT="tcp", GELF_HOST="127.0.0.1", GELF_PORT=port)
    for _ in range(2):
        visit(app, "/login", NORMAL)
    time.sleep(0.3)
    server = socket.socket()
    server.bind(("127.0.0.1", port))
    server.listen()
    server.settimeout(3)
    try:
        conn, _ = server.accept()
        conn.settimeout(2)
        logged = events(app)
        data = b""
        while data.count(b"\0") < len(logged):
            data += conn.recv(65535)
        conn.close()
    finally:
        server.close()
    frames = [json.loads(f) for f in data.split(b"\0") if f]
    original = {e["event_id"]: e["timestamp"] for e in logged}
    assert len(frames) == len(original)  # no duplicates
    assert {m["_event_id"]: json.loads(m["_portal_event"])["timestamp"] for m in frames} == original


# Keep last: its sender keeps retrying the unreachable port after the test ends.
def test_unreachable_gelf_tcp_does_not_delay_requests(app, monkeypatch):
    frontend(app)

    def stalled(*args, **kwargs):
        time.sleep(3)
        raise OSError("timed out")

    monkeypatch.setattr(socket, "create_connection", stalled)
    app.config.update(GELF_ENABLED=True, GELF_TRANSPORT="tcp", GELF_HOST="127.0.0.1", GELF_PORT=9)
    started = time.monotonic()
    for _ in range(3):
        assert visit(app, "/login", NORMAL).status_code == 200
    assert time.monotonic() - started < 1
