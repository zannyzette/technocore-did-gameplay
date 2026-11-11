"""_request: size limits, bad JSON, error bodies, redirects — local server only."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import technocore_agent as ta


def make_server(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


@pytest.fixture()
def base_url(monkeypatch):
    """Point _request at a local server; yields a setter for the handler."""
    holder = {}

    def _set(handler_cls):
        srv = make_server(handler_cls)
        holder["srv"] = srv
        monkeypatch.setattr(ta, "BASE_URL", f"http://127.0.0.1:{srv.server_address[1]}")
        return srv

    yield _set
    srv = holder.get("srv")
    if srv is not None:
        srv.shutdown()
        srv.server_close()


def _handler(body, status=200, content_type="application/json"):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            data = body() if callable(body) else body
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    return H


def test_non_json_body_is_clean_network_error(base_url):
    base_url(_handler(b"this is not json"))
    with pytest.raises(ta.NetworkError, match="invalid JSON"):
        ta._request("/r/lobby?format=json")


def test_invalid_utf8_body_is_clean_network_error(base_url):
    base_url(_handler(b"\xff\xfe\x00bad"))
    with pytest.raises(ta.NetworkError, match="invalid JSON"):
        ta._request("/r/lobby?format=json")


def test_oversized_json_body_rejected(base_url):
    big = json.dumps({"x": "A" * (ta.MAX_BODY_BYTES + 100)}).encode()
    base_url(_handler(big))
    with pytest.raises(ta.NetworkError, match="too large"):
        ta._request("/r/lobby?format=json")


def test_oversized_content_length_rejected_without_reading(base_url):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(ta.MAX_BODY_BYTES + 1))
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    base_url(H)
    with pytest.raises(ta.NetworkError, match="too large"):
        ta._request("/r/lobby?format=json")


def test_wrong_content_type_rejected(base_url):
    base_url(_handler(b"<html>nope</html>", content_type="text/html"))
    with pytest.raises(ta.NetworkError, match="unexpected Content-Type"):
        ta._request("/r/lobby?format=json")


def test_http_error_body_truncated_and_clean(base_url):
    # 1 MB error body: client must NOT read it whole (audit PoC), and the
    # error must be a clean NetworkError, not a traceback.
    base_url(_handler(b"E" * 1_000_000, status=500, content_type="text/plain"))
    with pytest.raises(ta.NetworkError, match="HTTP 500"):
        ta._request("/r/lobby?format=json")


def test_valid_json_still_works(base_url):
    base_url(_handler(json.dumps({"room": "lobby", "count": 0}).encode()))
    assert ta._request("/r/lobby?format=json") == {"room": "lobby", "count": 0}
