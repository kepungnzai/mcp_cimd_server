"""Tests for the MCP hello CIMD server."""

from __future__ import annotations

import json

import pytest

from mcp_hello_cimd.cimd import (
    CIMDFetchError,
    CIMDProcessor,
    CIMDValidationError,
    SSRFValidator,
)


# ---------------------------------------------------------------------------
# say_hello
# ---------------------------------------------------------------------------
async def test_say_hello():
    from mcp_hello_cimd.server import create_server

    server = create_server()
    tools = {t.name: t for t in await server.list_tools()}
    assert "say_hello" in tools

    _, result = await server.call_tool("say_hello", {"name": "world"})
    assert result == {"result": "Hello, world! Welcome to the MCP Hello CIMD server."}

    _, result2 = await server.call_tool("say_hello", {"name": "Alice"})
    assert result2 == {"result": "Hello, Alice! Welcome to the MCP Hello CIMD server."}


# ---------------------------------------------------------------------------
# SSRF validator
# ---------------------------------------------------------------------------
def test_ssrf_rejects_non_https():
    v = SSRFValidator()
    with pytest.raises(Exception):
        v.validate_url("http://client.example.com/metadata.json", resolve_dns=False)
    with pytest.raises(Exception):
        v.validate_url("file:///etc/passwd", resolve_dns=False)


def test_ssrf_rejects_missing_host():
    v = SSRFValidator()
    with pytest.raises(Exception):
        v.validate_url("https:///path", resolve_dns=False)


def test_ssrf_blocks_private_ip():
    v = SSRFValidator()
    with pytest.raises(Exception):
        v.validate_url("https://10.0.0.1/metadata.json")


def test_ssrf_accepts_public_url_format():
    v = SSRFValidator()
    url = v.validate_url(
        "https://client.example.com/metadata.json", resolve_dns=False
    )
    assert url == "https://client.example.com/metadata.json"


# ---------------------------------------------------------------------------
# CIMD schema validation
# ---------------------------------------------------------------------------
def test_schema_requires_client_id_match():
    p = CIMDProcessor()
    with pytest.raises(CIMDValidationError, match="client_id mismatch"):
        p._validate_schema(
            {
                "client_id": "https://other.example.com/meta.json",
                "redirect_uris": ["https://client.example.com/cb"],
            },
            "https://client.example.com/meta.json",
        )


def test_schema_requires_redirect_uris():
    p = CIMDProcessor()
    with pytest.raises(CIMDValidationError, match="redirect_uris"):
        p._validate_schema(
            {"client_id": "https://client.example.com/meta.json"},
            "https://client.example.com/meta.json",
        )


def test_schema_requires_https_redirect_uris():
    p = CIMDProcessor()
    with pytest.raises(CIMDValidationError, match="HTTPS"):
        p._validate_schema(
            {
                "client_id": "https://client.example.com/meta.json",
                "redirect_uris": ["http://client.example.com/cb"],
            },
            "https://client.example.com/meta.json",
        )


def test_schema_rejects_wildcards():
    p = CIMDProcessor()
    with pytest.raises(CIMDValidationError, match="Wildcards"):
        p._validate_schema(
            {
                "client_id": "https://client.example.com/meta.json",
                "redirect_uris": ["https://client.example.com/*"],
            },
            "https://client.example.com/meta.json",
        )


def test_schema_valid_document():
    p = CIMDProcessor()
    doc = {
        "client_id": "https://client.example.com/meta.json",
        "client_name": "Example",
        "redirect_uris": ["https://client.example.com/cb"],
        "client_uri": "https://client.example.com",
    }
    p._validate_schema(doc, "https://client.example.com/meta.json")  # no raise


# ---------------------------------------------------------------------------
# CIMD resolve with mocked fetch
# ---------------------------------------------------------------------------
def _skip_dns(validator):
    """Monkeypatch helper: make validator skip real DNS resolution."""

    def fake_validate_url(url, resolve_dns=True):
        return url

    def fake_lookup(url):
        return url, "93.184.216.34"

    validator.validate_url = fake_validate_url
    validator.lookup = fake_lookup


def test_resolve_fetch_and_cache(monkeypatch):
    p = CIMDProcessor(ttl=600)
    client_id = "https://client.example.com/meta.json"
    doc = {
        "client_id": client_id,
        "client_name": "Example",
        "redirect_uris": ["https://client.example.com/cb"],
    }
    body = json.dumps(doc).encode()

    calls = {"n": 0}

    def fake_fetch(cid):
        calls["n"] += 1
        return body

    monkeypatch.setattr(p, "_fetch", fake_fetch)
    _skip_dns(p.validator)

    result = p.resolve(client_id)
    assert result["client_name"] == "Example"
    assert calls["n"] == 1

    result2 = p.resolve(client_id)
    assert result2["client_name"] == "Example"
    assert calls["n"] == 1  # served from cache

    info = p.cache_info()
    assert client_id in info
    assert 0 < info[client_id] <= 600

    p.clear_cache()
    p.resolve(client_id)
    assert calls["n"] == 2  # cache cleared -> refetch


def test_resolve_rejects_http():
    p = CIMDProcessor()
    with pytest.raises(CIMDValidationError, match="HTTPS"):
        p.resolve("http://client.example.com/meta.json")


def test_resolve_fetch_error(monkeypatch):
    p = CIMDProcessor()

    def fake_fetch(cid):
        raise CIMDFetchError("Unable to fetch client metadata from specified URL")

    monkeypatch.setattr(p, "_fetch", fake_fetch)
    _skip_dns(p.validator)
    with pytest.raises(CIMDFetchError):
        p.resolve("https://client.example.com/meta.json")


def test_resolve_invalid_json(monkeypatch):
    p = CIMDProcessor()
    monkeypatch.setattr(p, "_fetch", lambda cid: b"{not json")
    _skip_dns(p.validator)
    with pytest.raises(CIMDValidationError, match="valid JSON"):
        p.resolve("https://client.example.com/meta.json")


def test_resolve_missing_client_id(monkeypatch):
    p = CIMDProcessor()
    monkeypatch.setattr(
        p,
        "_fetch",
        lambda cid: json.dumps({"redirect_uris": ["https://x/cb"]}).encode(),
    )
    _skip_dns(p.validator)
    with pytest.raises(CIMDValidationError, match="client_id"):
        p.resolve("https://client.example.com/meta.json")


def _http_response(body_bytes, status=200, content_type="application/json", headers=None):
    """Build a fake http.client-style response object."""

    class _FakeHTTPS:
        def __init__(self):
            self.status = status
            self._d = {"content-type": content_type, "content-length": str(len(body_bytes))}
            if headers:
                for k, v in headers.items():
                    self._d[k.lower()] = v
            self._body = body_bytes
            self.closed = False

        def getheader(self, key, default=None):
            return self._d.get(key.lower(), default)

        def read(self, n=-1):
            return self._body if n < 0 else self._body[:n]

        def close(self):
            self.closed = True

    return _FakeHTTPS()


def _fake_conn_class(handler):
    """Create a fake HTTPSConnection class whose getresponse calls handler()."""

    class _FakeConnection:
        def __init__(self, host, port=443, timeout=None, context=None, server_hostname=None):
            self.host = host
            self.request_path = None

        def request(self, method, path, headers=None):
            self.request_path = path

        def getresponse(self):
            return handler(self)

        def close(self):
            pass

    return _FakeConnection


def test_fetch_respects_size_limit(monkeypatch):
    import http.client

    p = CIMDProcessor(max_size=100)
    big = b"x" * 200

    def handler(conn):
        return _http_response(big, content_type="application/json")

    monkeypatch.setattr(http.client, "HTTPSConnection", _fake_conn_class(handler))
    monkeypatch.setattr(p, "_ssl_context", lambda: None)
    monkeypatch.setattr(p.validator, "lookup", lambda url: (url, "93.184.216.34"))
    monkeypatch.setattr(p.validator, "validate_url", lambda url: url)

    with pytest.raises(CIMDFetchError, match="too large"):
        p._fetch("https://client.example.com/meta.json")


def test_fetch_rejects_wrong_content_type(monkeypatch):
    import http.client

    p = CIMDProcessor()

    def handler(conn):
        return _http_response(b"{}", content_type="text/html")

    monkeypatch.setattr(http.client, "HTTPSConnection", _fake_conn_class(handler))
    monkeypatch.setattr(p, "_ssl_context", lambda: None)
    monkeypatch.setattr(p.validator, "lookup", lambda url: (url, "93.184.216.34"))
    monkeypatch.setattr(p.validator, "validate_url", lambda url: url)

    with pytest.raises(CIMDFetchError, match="Content-Type"):
        p._fetch("https://client.example.com/meta.json")


def test_fetch_follows_redirects(monkeypatch):
    import http.client

    p = CIMDProcessor(max_redirects=3)
    doc = json.dumps(
        {
            "client_id": "https://client.example.com/meta.json",
            "redirect_uris": ["https://client.example.com/cb"],
        }
    ).encode()

    hops = []

    def handler(conn):
        hops.append(conn.request_path)
        if conn.request_path == "/meta.json" and len(hops) == 1:
            return _http_response(
                b"",
                status=302,
                content_type="application/json",
                headers={"Location": "/meta.json"},
            )
        return _http_response(doc, status=200, content_type="application/json")

    monkeypatch.setattr(http.client, "HTTPSConnection", _fake_conn_class(handler))
    monkeypatch.setattr(p, "_ssl_context", lambda: None)
    monkeypatch.setattr(
        p.validator,
        "lookup",
        lambda url: ("https://old.example.com/meta.json", "93.184.216.34"),
    )
    monkeypatch.setattr(p.validator, "validate_url", lambda url: url)

    body = p._fetch("https://old.example.com/meta.json")
    assert json.loads(body)["client_id"] == "https://client.example.com/meta.json"


def test_fetch_exceeds_redirect_limit(monkeypatch):
    import http.client

    p = CIMDProcessor(max_redirects=2)

    def handler(conn):
        return _http_response(
            b"",
            status=302,
            content_type="application/json",
            headers={"Location": "https://client.example.com/next"},
        )

    monkeypatch.setattr(http.client, "HTTPSConnection", _fake_conn_class(handler))
    monkeypatch.setattr(p, "_ssl_context", lambda: None)
    monkeypatch.setattr(p.validator, "lookup", lambda url: (url, "93.184.216.34"))
    monkeypatch.setattr(p.validator, "validate_url", lambda url: url)

    with pytest.raises(CIMDFetchError, match="Too many redirects"):
        p._fetch("https://client.example.com/meta.json")


def test_health_check_endpoint():
    from starlette.testclient import TestClient
    from mcp_hello_cimd.cli import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

