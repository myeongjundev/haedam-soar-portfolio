"""Run migrations and the backend suite against an isolated disposable MySQL 8.4.

Owns only its uniquely named container, generated password and random loopback port.
No existing containers or application databases are touched.
"""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.parse import quote

import pymysql

root = Path(__file__).resolve().parents[1]
name = "haedam-mysql-qa-" + secrets.token_hex(5)
env = os.environ.copy()
password = secrets.token_urlsafe(30)
env["MYSQL_ROOT_PASSWORD"] = password
env["MYSQL_DATABASE"] = "haedam_qa"

def run(args, **kwargs):
    return subprocess.run(args, cwd=root, check=True, **kwargs)

try:
    run(["docker", "run", "--detach", "--rm", "--name", name, "--memory", "768m", "--cpus", "1",
         "--env", "MYSQL_ROOT_PASSWORD", "--env", "MYSQL_DATABASE", "--publish", "127.0.0.1::3306", "mysql:8.4"], env=env, stdout=subprocess.DEVNULL)
    port = subprocess.check_output(["docker", "port", name, "3306/tcp"], text=True).strip().rsplit(":", 1)[1]
    deadline = time.monotonic() + 120
    while True:
        try:
            connection = pymysql.connect(host="127.0.0.1", port=int(port), user="root", password=password, database="haedam_qa", connect_timeout=2)
            connection.close()
            break
        except pymysql.Error:
            if time.monotonic() > deadline:
                raise RuntimeError("Disposable MySQL did not become ready") from None
            time.sleep(2)
    url = f"mysql+pymysql://root:{quote(password)}@127.0.0.1:{port}/haedam_qa?charset=utf8mb4"
    env["DATABASE_URL"] = url
    env["HAEDAM_TEST_DATABASE_URL"] = url
    env["HAEDAM_TEST_ALLOW_DISPOSABLE"] = "1"
    # Credentials stay only in child environment; never print a connection URL.
    print("Disposable MySQL 8.4 ready. Checking migrations and isolated tests.", flush=True)
    run([sys.executable, "-m", "flask", "--app", "haedam_portal:create_app", "db", "upgrade"], env=env)
    run([sys.executable, "-m", "flask", "--app", "haedam_portal:create_app", "db", "check"], env=env)
    # Exercise rollback only on this empty, disposable migration database.
    run([sys.executable, "-m", "flask", "--app", "haedam_portal:create_app", "db", "downgrade", "base"], env=env)
    run([sys.executable, "-m", "flask", "--app", "haedam_portal:create_app", "db", "upgrade"], env=env)
    run([sys.executable, "-m", "pytest", "-q"], env=env)
finally:
    subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
