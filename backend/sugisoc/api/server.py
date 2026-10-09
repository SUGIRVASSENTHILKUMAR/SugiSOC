"""Local-only SugiSOC dashboard API using the existing evidence stores."""

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from sugisoc.correlation.cases import CaseStore
from sugisoc.detection.alert_store import AlertStore
from sugisoc.services.event_store import EventStore

ROOT = Path(__file__).resolve().parents[3]
FRONTEND = ROOT / "frontend"
MAX_BODY = 8192


def create_handler(database: Path):
    """Build an HTTP handler bound to a particular SQLite evidence database."""
    events = EventStore(database)
    alerts = AlertStore(database)
    cases = CaseStore(database)

    class Handler(BaseHTTPRequestHandler):
        def _json(self, data, status=200):
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
            )
            self.end_headers()
            self.wfile.write(body)

        def _static(self, name):
            allowed = {
                "/": "index.html",
                "/index.html": "index.html",
                "/style.css": "style.css",
                "/app.js": "app.js",
            }
            if name not in allowed:
                return self._json({"error": "Not found"}, 404)
            file = FRONTEND / allowed[name]
            raw = file.read_bytes()
            self.send_response(200)
            self.send_header(
                "Content-Type", mimetypes.guess_type(file.name)[0] or "application/octet-stream"
            )
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):  # noqa: N802
            parsed = urlsplit(self.path)
            path = parsed.path
            params = parse_qs(parsed.query)
            if path == "/api/overview":
                a = alerts.list_alerts()
                c = cases.list_cases()
                return self._json(
                    {
                        "events": events.count(),
                        "alerts": len(a),
                        "high_alerts": sum(x["severity"] in {"high", "critical"} for x in a),
                        "open_cases": sum(x["status"] != "closed" for x in c),
                        "cases": len(c),
                    }
                )
            if path == "/api/alerts":
                return self._json(alerts.list_alerts()[:200])
            if path == "/api/cases":
                return self._json(cases.list_cases()[:200])
            if path.startswith("/api/cases/"):
                case_id = path.removeprefix("/api/cases/")
                if not case_id or "/" in case_id or len(case_id) > 100:
                    return self._json({"error": "Invalid case ID"}, 400)
                item = cases.investigation(case_id)
                return self._json(
                    item if item is not None else {"error": "Case not found"}, 200 if item else 404
                )
            if path == "/api/events":
                try:
                    limit = int(params.get("limit", ["100"])[0])
                    offset = int(params.get("offset", ["0"])[0])
                    results = events.search(
                        limit=limit,
                        offset=offset,
                        username=params.get("username", [None])[0] or None,
                        source_ip=params.get("ip", [None])[0] or None,
                        event_type=params.get("type", [None])[0] or None,
                    )
                except (ValueError, TypeError):
                    return self._json({"error": "Invalid search parameters"}, 400)
                return self._json(results)
            return self._static(path)

        def do_POST(self):  # noqa: N802
            parsed = urlsplit(self.path)
            path = parsed.path
            if not (path.startswith("/api/cases/") and path.endswith(("/status", "/notes"))):
                return self._json({"error": "Not found"}, 404)
            size = self.headers.get("Content-Length", "")
            if not size.isdecimal() or int(size) > MAX_BODY:
                return self._json({"error": "Invalid body length"}, 400)
            try:
                data = json.loads(self.rfile.read(int(size)))
                if not isinstance(data, dict):
                    raise ValueError("Expected an object")
                case_id, action = path.removeprefix("/api/cases/").rsplit("/", 1)
                if not case_id or "/" in case_id or len(case_id) > 100:
                    raise ValueError("Invalid case ID")
                if action == "status":
                    if not isinstance(data.get("status"), str):
                        raise ValueError("Invalid status")
                    found = cases.set_status(case_id, data["status"])
                    return self._json({"ok": found}, 200 if found else 404)
                if not isinstance(data.get("analyst"), str) or not isinstance(
                    data.get("body"), str
                ):
                    raise ValueError("Invalid note")
                note_id = cases.add_note(case_id, data["analyst"], data["body"])
                return self._json({"note_id": note_id}, 201)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return self._json({"error": str(exc)}, 400)
            except KeyError:
                return self._json({"error": "Case not found"}, 404)

    return Handler


def serve(database: Path, port: int = 8765):
    """Bind only on the loopback interface; no public authentication is provided."""
    with ThreadingHTTPServer(("127.0.0.1", port), create_handler(database)) as server:
        print(f"SugiSOC local dashboard: http://127.0.0.1:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run local SugiSOC dashboard")
    parser.add_argument("--database", type=Path, default=Path(".collection-state/sugisoc.sqlite3"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    serve(args.database, args.port)
