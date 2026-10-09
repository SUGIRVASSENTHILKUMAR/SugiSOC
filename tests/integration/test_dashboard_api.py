"""Phase 06: local dashboard HTTP API and frontend contract checks."""

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from sugisoc.api.server import FRONTEND, create_handler
from sugisoc.correlation.cases import CaseStore
from sugisoc.detection.alert_store import AlertStore
from sugisoc.services.event_store import EventStore


@pytest.fixture
def server(tmp_path: Path):
    database = tmp_path / "test.sqlite3"
    EventStore(database)
    AlertStore(database)
    CaseStore(database)
    http = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(database))
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{http.server_port}"
    http.shutdown()
    thread.join(timeout=5)
    http.server_close()


def read_json(url: str):
    with urlopen(url, timeout=3) as reply:
        return json.load(reply)


def test_overview_is_real_and_empty(server: str):
    assert read_json(server + "/api/overview") == {
        "events": 0,
        "alerts": 0,
        "high_alerts": 0,
        "open_cases": 0,
        "cases": 0,
    }


def test_event_search_and_cases_are_empty(server: str):
    assert read_json(server + "/api/events?limit=25") == []
    assert read_json(server + "/api/alerts") == []
    assert read_json(server + "/api/cases") == []


def test_invalid_pagination_is_rejected(server: str):
    with pytest.raises(HTTPError) as err:
        read_json(server + "/api/events?limit=10000")
    assert err.value.code == 400


def test_unknown_case_is_404(server: str):
    with pytest.raises(HTTPError) as err:
        read_json(server + "/api/cases/missing")
    assert err.value.code == 404


def test_invalid_status_body_is_rejected(server: str):
    request = Request(
        server + "/api/cases/missing/status",
        data=json.dumps({"status": "invalid"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(HTTPError) as err:
        urlopen(request, timeout=3)
    assert err.value.code == 400


def test_frontend_served_with_security_headers(server: str):
    with urlopen(server + "/", timeout=3) as response:
        assert b"SugiSOC" in response.read()
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert (FRONTEND / "app.js").is_file()


def test_arbitrary_static_paths_not_exposed(server: str):
    with pytest.raises(HTTPError) as err:
        urlopen(server + "/.git/config", timeout=3)
    assert err.value.code == 404
