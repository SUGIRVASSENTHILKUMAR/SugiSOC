"""Browser-origin and API security regression tests for local investigation writes."""

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from sugisoc.api.server import create_handler


@pytest.fixture
def local_api(tmp_path: Path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(tmp_path / "audit.sqlite3"))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()


def post(base: str, *, origin: str | None = None, body: bytes = b"{}"):
    headers = {"Content-Type": "application/json"}
    if origin is not None:
        headers["Origin"] = origin
    return Request(
        base + "/api/cases/nonexistent/status", data=body, headers=headers, method="POST"
    )


def test_cross_site_post_is_forbidden(local_api: str):
    with pytest.raises(HTTPError) as error:
        urlopen(post(local_api, origin="https://attacker.example"), timeout=4)
    assert error.value.code == 403


def test_same_origin_request_reaches_normal_validation(local_api: str):
    with pytest.raises(HTTPError) as error:
        urlopen(post(local_api, origin=local_api, body=b'{"status":"wrong"}'), timeout=4)
    assert error.value.code == 400


def test_invalid_origin_is_rejected(local_api: str):
    with pytest.raises(HTTPError) as error:
        urlopen(post(local_api, origin="null"), timeout=4)
    assert error.value.code == 403


def test_oversized_request_fails(local_api: str):
    with pytest.raises(HTTPError) as error:
        urlopen(post(local_api, body=json.dumps({"data": "a" * 9000}).encode()), timeout=4)
    assert error.value.code == 400


def test_private_git_file_is_not_served(local_api: str):
    with pytest.raises(HTTPError) as error:
        urlopen(local_api + "/.git/config", timeout=4)
    assert error.value.code == 404


def test_read_only_demo_rejects_all_writes(tmp_path: Path):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        create_handler(tmp_path / "readonly.sqlite3", read_only=True),
    )
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"

        with urlopen(base + "/api/overview", timeout=4) as response:
            assert response.status == 200
            assert json.load(response)["events"] == 0

        for origin in (None, base, "https://attacker.example"):
            with pytest.raises(HTTPError) as error:
                urlopen(post(base, origin=origin), timeout=4)
            assert error.value.code == 405

        for path in (
            "/api/cases/example/status",
            "/api/cases/example/notes",
        ):
            request = Request(
                base + path,
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(HTTPError) as error:
                urlopen(request, timeout=4)
            assert error.value.code == 405
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
