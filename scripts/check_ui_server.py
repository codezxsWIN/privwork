"""Human-approved loopback smoke check, separate from socket-free unittests.

Contacts only an ephemeral 127.0.0.1 viewer and stops it before returning.
Does not run scanners, fetch feeds, contact models, or write assessment records.
"""

import argparse
import json
import sqlite3
import sys
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from urllib.parse import quote


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=root / "data" / "vulnassess.db")
    parser.add_argument("--config", type=Path, default=root / "config")
    parser.add_argument("--run", default="demo")
    arguments = parser.parse_args()
    sys.path.insert(0, str(root))
    from vulnassess.errors import ConfigError
    from vulnassess.ui.server import UiApplication, UiServer

    try:
        application = UiApplication(arguments.db, arguments.config, arguments.run)
        database = Path(application.database)
        before = sha256(database.read_bytes()).hexdigest()
        server = UiServer(application, port=0)
    except ConfigError as error:
        print(f"ConfigError: {error}")
        return error.exit_code
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    worker.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        print(f"BOUND: 127.0.0.1:{server.server_port}")
        targets = (
            ("GET", "/", 200),
            ("GET", "/workflow", 200),
            ("GET", "/static/workflow.css", 200),
            ("GET", "/static/workflow.js", 200),
            ("GET", "/static/workflow-data.js", 200),
            ("GET", "/static/tokens.css", 200),
            ("GET", "/static/workbench.css", 200),
            ("GET", "/static/app.js", 200),
            ("GET", "/static/cvss31.js", 200),
            ("GET", "/api/cvss-fixture", 200),
            ("GET", "/static/buildings/door.svg", 200),
            ("GET", "/api/runs", 200),
            ("GET", f"/api/run/{quote(arguments.run, safe='')}", 200),
            ("GET", "/api/model", 404),
            ("GET", "/api/model/run", 404),
            ("POST", "/api/model/run", 405),
            ("GET", "/static/../../config/scope.yaml", 404),
            ("POST", "/api/runs", 405),
            ("PUT", "/api/runs", 405),
            ("DELETE", "/api/runs", 405),
        )
        for method, target, expected in targets:
            if method == "POST" and target == "/api/model/run":
                connection.request(
                    method,
                    target,
                    json.dumps({"run_id": arguments.run}),
                    headers={
                        "Origin": f"http://127.0.0.1:{server.server_port}",
                        "X-Vulnassess-Action": "run-model",
                        "Content-Type": "application/json",
                    },
                )
            else:
                connection.request(method, target)
            response = connection.getresponse()
            body = response.read()
            print(f"{method} {target} -> {response.status}")
            assert response.status == expected, (method, target, response.status)
            assert "default-src 'self'" in (response.getheader("Content-Security-Policy") or "")
            if expected == 405:
                assert response.getheader("Allow") == "GET"
            if target.startswith("/api/run/"):
                actual = json.loads(body)["scores"]
                stored = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
                try:
                    rows = stored.execute(
                        "SELECT json FROM scores WHERE run_id = ? ORDER BY risk DESC, finding_id",
                        (arguments.run,),
                    ).fetchall()
                finally:
                    stored.close()
                assert actual == [json.loads(row[0]) for row in rows]
                print(f"SCORES: {len(actual)} API records equal stored JSON")
    finally:
        connection.close()
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
    assert not worker.is_alive(), "UI smoke server did not stop"
    assert sha256(database.read_bytes()).hexdigest() == before, "database bytes changed"
    print("DATABASE: SHA-256 unchanged")
    print("SERVER: stopped")
    print("UI LOOPBACK SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
