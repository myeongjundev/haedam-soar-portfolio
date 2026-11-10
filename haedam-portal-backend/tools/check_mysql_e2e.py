"""Build React and run browser tests on an owned disposable MySQL/Waitress stack.

The local file handshake can replace only this runner's child process. No restart
HTTP endpoint, browser credentials file, or existing database/container is used.
"""
import json
import os
import re
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from contextlib import ExitStack
from urllib.parse import quote
from urllib.request import urlopen

import pymysql

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT.parent / "haedam-portal-frontend"
IMAGE = "mysql@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    # The existing SQLite preview (5000) is never touched; do not claim an occupied QA port.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 5005))
    if not (FRONTEND / "node_modules/@playwright/test/cli.js").is_file():
        raise RuntimeError("Prepare the sibling frontend with npm ci first")
    name = "haedam-mysql-e2e-" + secrets.token_hex(5)
    password, root_password = secrets.token_urlsafe(30), secrets.token_urlsafe(30)
    environment = os.environ.copy()
    environment.update(MYSQL_ROOT_PASSWORD=root_password, MYSQL_DATABASE="haedam_e2e",
                       MYSQL_USER="haedam_e2e", MYSQL_PASSWORD=password)
    server = browser = None
    container_started = False
    log_handle = None
    restarts = []
    url = ""

    def sanitized(value):
        for secret in (url, password, root_password):
            if secret:
                value = value.replace(secret, "[redacted]")
        return value

    def run(arguments, cwd=ROOT, env=None):
        result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        if result.stdout:
            print(sanitized(result.stdout), end="", flush=True)
        if result.stderr:
            print(sanitized(result.stderr), end="", file=sys.stderr, flush=True)
        if result.returncode:
            raise RuntimeError("Verification subprocess failed (see sanitized output above)")
        return result.stdout

    def stop(process):
        if process and process.poll() is None:
            if os.name == "nt":
                # venv's Windows launcher has a separate interpreter child. Own
                # the entire spawned tree, including that child and its listener.
                result = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                if result.returncode and process.poll() is None:
                    raise RuntimeError("Could not stop the owned QA process tree")
            else:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    try:
        subprocess.run(["docker", "run", "--detach", "--rm", "--name", name,
                        "--memory", "768m", "--cpus", "1", "--env", "MYSQL_ROOT_PASSWORD",
                        "--env", "MYSQL_DATABASE", "--env", "MYSQL_USER", "--env", "MYSQL_PASSWORD",
                        "--publish", "127.0.0.1::3306", IMAGE], env=environment,
                       stdout=subprocess.DEVNULL, check=True)
        container_started = True
        port = int(subprocess.check_output(["docker", "port", name, "3306/tcp"], text=True).strip().rsplit(":", 1)[1])
        connection_options = dict(host="127.0.0.1", port=port, user="haedam_e2e",
                                  password=password, database="haedam_e2e", charset="utf8mb4", connect_timeout=2)
        deadline = time.monotonic() + 120
        while True:
            try:
                with pymysql.connect(**connection_options) as connection, connection.cursor() as cursor:
                    cursor.execute("SELECT VERSION()")
                    version = cursor.fetchone()[0]
                break
            except pymysql.Error:
                if time.monotonic() > deadline:
                    raise RuntimeError("Disposable MySQL did not become ready") from None
                time.sleep(1)
        url = f"mysql+pymysql://haedam_e2e:{quote(password)}@127.0.0.1:{port}/haedam_e2e?charset=utf8mb4"
        print(f"Disposable MySQL {version} ready; building React.", flush=True)
        run(["node", "node_modules/vite/bin/vite.js", "build"], cwd=FRONTEND)
        with tempfile.TemporaryDirectory(prefix="haedam-mysql-browser-") as temporary, ExitStack() as cleanup:
            control = Path(temporary)
            ready_file = control / "ready.json"
            server_env = os.environ.copy()
            server_env.update(HAEDAM_E2E_DATABASE_URL=url, HAEDAM_E2E_ALLOW_DISPOSABLE="1",
                              HAEDAM_E2E_READY_FILE=str(ready_file), HAEDAM_E2E_RUNTIME_ROOT=str(control),
                              FRONTEND_DIST=str(FRONTEND / "dist"),
                              PYTHONIOENCODING="utf-8", GELF_ENABLED="0")
            log_handle = (control / "server.log").open("w+", encoding="utf-8")
            cleanup.callback(log_handle.close)
            cleanup.callback(lambda: stop(server))
            cleanup.callback(lambda: stop(browser))

            def start():
                ready_file.unlink(missing_ok=True)
                process = subprocess.Popen([sys.executable, str(ROOT / "tools/e2e_server.py")], cwd=ROOT,
                                           env=server_env, stdout=log_handle, stderr=subprocess.STDOUT)
                try:
                    until = time.monotonic() + 45
                    while time.monotonic() < until:
                        if process.poll() is not None:
                            raise RuntimeError("Owned Waitress child exited before readiness")
                        try:
                            metadata = json.loads(ready_file.read_text(encoding="utf-8"))
                            owned = metadata["pid"] == process.pid or metadata["parent_pid"] == process.pid
                            if owned and metadata["dialect"] == "mysql" and metadata["database"] == "haedam_e2e":
                                with urlopen("http://127.0.0.1:5005/api/v1/health", timeout=1) as response:
                                    if response.status == 200:
                                        process.server_pid = metadata["pid"]
                                        return process
                        except (OSError, ValueError):
                            pass
                        time.sleep(0.2)
                    raise RuntimeError("Owned MySQL/Waitress child did not become ready")
                except BaseException:
                    stop(process)
                    print(sanitized((control / "server.log").read_text(encoding="utf-8", errors="replace")[-8000:]), file=sys.stderr)
                    raise

            server = start()
            # Credentials are inherited only by the backend, never the browser runner.
            browser_env = os.environ.copy()
            for key in ("DATABASE_URL", "HAEDAM_TEST_DATABASE_URL", "HAEDAM_E2E_DATABASE_URL", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD"):
                browser_env.pop(key, None)
            browser_env.update(HAEDAM_E2E_MYSQL="1", HAEDAM_E2E_CONTROL_DIR=str(control))
            print("Running browser suite against MySQL; two owned Waitress process replacements are enabled.", flush=True)
            with (control / "browser.log").open("w+", encoding="utf-8") as browser_log:
                browser = subprocess.Popen(["node", "node_modules/@playwright/test/cli.js", "test"],
                                           cwd=FRONTEND, env=browser_env, stdout=browser_log, stderr=subprocess.STDOUT)
                handled = set()
                deadline = time.monotonic() + 240
                while browser.poll() is None:
                    if time.monotonic() > deadline:
                        raise RuntimeError("MySQL browser suite exceeded 240 seconds")
                    request_file = control / "restart-request.json"
                    try:
                        request = json.loads(request_file.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        request = {}
                    request_id = request.get("id")
                    if request_id in (1, 2) and request_id not in handled and request.get("action") == "restart":
                        old_pid = server.server_pid
                        stop(server)
                        server = start()
                        assert server.server_pid != old_pid
                        acknowledgement = {"id":request_id, "previous_pid":old_pid,
                                           "current_pid":server.server_pid, "dialect":"mysql"}
                        restarts.append(acknowledgement)
                        pending = control / "restart-response.tmp"
                        pending.write_text(json.dumps(acknowledgement), encoding="utf-8")
                        pending.replace(control / "restart-response.json")
                        handled.add(request_id)
                        print(f"Waitress restart {request_id}: PID {old_pid} -> {server.server_pid}; MySQL health 200.", flush=True)
                    time.sleep(0.1)
                browser_log.flush()
                browser_log.seek(0)
                output = browser_log.read()
                print(sanitized(output), end="", flush=True)
                if browser.returncode:
                    raise RuntimeError("MySQL browser suite failed")
                count = re.search(r"\b(\d+) passed\b", output)
                assert count and int(count[1]) > 0, "Browser runner must report passing tests"
            assert len(restarts) == 2, "Both persistence checkpoints must actually replace Waitress"
            # Independent, read-only MySQL audit complements the UI/API assertions.
            with pymysql.connect(**connection_options) as connection, connection.cursor() as cursor:
                cursor.execute("SELECT p.id,p.status,p.version,p.title,p.content,p.reply FROM petitions p JOIN users u ON u.id=p.applicant_id WHERE u.username=%s", ("mysql_persist",))
                rows = cursor.fetchall()
                assert len(rows) == 1
                petition_id, status, revision, title, content, reply = rows[0]
                assert status == "completed" and "🌱" in title and "🌱" in content and "🌱" in reply
                cursor.execute("SELECT from_status,to_status FROM petition_history WHERE petition_id=%s ORDER BY id", (petition_id,))
                history = [list(row) for row in cursor.fetchall()]
                assert history == [[None,"received"],["received","received"],["received","in_progress"],["in_progress","completed"]]
                cursor.execute("SELECT version_num FROM alembic_version")
                migration = cursor.fetchone()[0]
            # Check ORM/schema agreement using the same disposable DB and no reset.
            migration_env = server_env | {"DATABASE_URL":url}
            run([sys.executable, "-m", "flask", "--app", "haedam_portal:create_app", "db", "check"], env=migration_env)
            report = {"checked_at":datetime.now(timezone.utc).isoformat(), "mysql_version":version,
                      "image":IMAGE, "database":"haedam_e2e", "browser_suite":f"{count[1]} passed",
                      "waitress_restarts":restarts, "mysql_readonly_audit":{"petition_id":petition_id,
                      "status":status, "version":revision, "history":history, "utf8mb4_round_trip":True,
                      "migration_revision":migration}, "schema_drift":False}
            target = ROOT / ".local/mysql-e2e-report.json"
            target.parent.mkdir(exist_ok=True)
            target.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
            print("MySQL browser integration, process restart persistence and read-only DB audit passed.", flush=True)
    finally:
        stop(browser)
        stop(server)
        if log_handle:
            log_handle.close()
        if container_started:
            subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print("Owned QA server and disposable MySQL container removed.", flush=True)


if __name__ == "__main__":
    main()
