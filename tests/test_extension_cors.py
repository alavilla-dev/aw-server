"""Tests for moz-extension CORS endpoint scoping (extension_cors module)."""

import pytest

from aw_server.extension_cors import (
    _is_allowed,
    _is_allowed_path,
    _matches_configured_origin,
)
from aw_server.server import AWFlask

_EXT_ORIGIN = "moz-extension://aabbccddeeff00112233445566778899"
_HOST = "127.0.0.1"


@pytest.fixture(scope="module")
def client():
    app = AWFlask(_HOST, testing=True)
    return app.test_client()


# ---------------------------------------------------------------------------
# Unit tests for the path-matching helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,expected",
    [
        ("GET", "/api/0/info", True),
        ("POST", "/api/0/buckets/aw-watcher-web-hostname", True),
        ("POST", "/api/0/buckets/aw-watcher-web-hostname/heartbeat", True),
        # Blocked paths
        ("GET", "/api/0/export", False),
        ("POST", "/api/0/export", False),
        ("GET", "/api/0/buckets/", False),
        ("GET", "/api/0/buckets/aw-watcher-web-hostname/events", False),
        ("POST", "/api/0/query/", False),
        ("GET", "/api/0/settings", False),
        # Non-watcher bucket
        ("POST", "/api/0/buckets/aw-watcher-window-hostname", False),
        # Heartbeat on non-watcher bucket
        ("POST", "/api/0/buckets/aw-watcher-afk-hostname/heartbeat", False),
        # Percent-encoding should not bypass via raw path (segments are used)
        ("GET", "/api/0/%65xport", False),  # %65 = 'e', decodes to 'export'
    ],
)
def test_is_allowed_unit(method, path, expected):
    segments = [s for s in path.split("/") if s]
    assert _is_allowed(method, segments) is expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api/0/info", True),
        ("/api/0/buckets/aw-watcher-web-hostname", True),
        ("/api/0/buckets/aw-watcher-web-hostname/heartbeat", True),
        ("/api/0/export", False),
        ("/api/0/buckets/", False),
    ],
)
def test_is_allowed_path_unit(path, expected):
    segments = [s for s in path.split("/") if s]
    assert _is_allowed_path(segments) is expected


# ---------------------------------------------------------------------------
# Integration tests via Flask test client
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/0/info"),
        # Bucket creation: 400 without body is expected but NOT 403
        ("POST", "/api/0/buckets/aw-watcher-web-testhost"),
        # Heartbeat: 404 (bucket doesn't exist) is expected but NOT 403
        ("POST", "/api/0/buckets/aw-watcher-web-testhost/heartbeat"),
    ],
)
def test_extension_allowed(client, method, path):
    """moz-extension origins are permitted at aw-watcher-web's endpoints."""
    headers = {"Origin": _EXT_ORIGIN}
    r = client.open(path, method=method, headers=headers)
    assert (
        r.status_code != 403
    ), f"{method} {path} should not be blocked; got {r.status_code}"


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/0/export"),
        ("GET", "/api/0/buckets/"),
        ("POST", "/api/0/import"),
        ("POST", "/api/0/query/"),
        ("GET", "/api/0/settings"),
        # Events read from a watcher bucket
        ("GET", "/api/0/buckets/aw-watcher-web-testhost/events"),
        # Non-watcher bucket
        ("POST", "/api/0/buckets/aw-watcher-window-testhost"),
        ("POST", "/api/0/buckets/aw-watcher-afk-testhost/heartbeat"),
    ],
)
def test_extension_blocked(client, method, path):
    """moz-extension origins are blocked at endpoints beyond aw-watcher-web's needs."""
    headers = {"Origin": _EXT_ORIGIN}
    r = client.open(path, method=method, headers=headers)
    assert (
        r.status_code == 403
    ), f"{method} {path} should be blocked (403); got {r.status_code}"


@pytest.mark.parametrize(
    "pattern,origin,expected",
    [
        ("moz-extension://aabbcc", "moz-extension://aabbcc", True),
        ("MOZ-EXTENSION://AABBCC", "moz-extension://aabbcc", True),
        (r"moz-extension://.*", "moz-extension://aabbcc", True),
        (r"moz-extension://[a-f0-9]+", "moz-extension://aabbcc", True),
        (r"moz-extension://[0-9]+", "moz-extension://aabbcc", False),
        ("moz-extension://other", "moz-extension://aabbcc", False),
    ],
)
def test_matches_configured_origin(pattern, origin, expected):
    assert _matches_configured_origin(origin, pattern) is expected


def test_regex_configured_extension_origin_bypasses_scope_guard():
    """Owner-configured regex origins retain unrestricted endpoint access."""
    app = AWFlask(_HOST, testing=False, cors_origins=[r"moz-extension://.*"])
    client = app.test_client()

    response = client.get("/api/0/export", headers={"Origin": _EXT_ORIGIN})

    assert response.status_code != 403


def test_non_extension_origin_passthrough(client):
    """Non-moz-extension origins are not affected by the scope guard."""
    headers = {"Origin": "http://127.0.0.1:27180"}
    r = client.get("/api/0/info", headers=headers)
    assert r.status_code != 403


def test_no_origin_passthrough(client):
    """Requests without an Origin header (native watchers, curl) are not blocked."""
    r = client.get("/api/0/info")
    assert r.status_code != 403


def test_options_allowed_path(client):
    """OPTIONS preflight on an allowed path is permitted."""
    headers = {
        "Origin": _EXT_ORIGIN,
        "Access-Control-Request-Method": "GET",
    }
    r = client.options("/api/0/info", headers=headers)
    assert r.status_code != 403


def test_options_blocked_path(client):
    """OPTIONS preflight on a blocked path is rejected."""
    headers = {
        "Origin": _EXT_ORIGIN,
        "Access-Control-Request-Method": "GET",
    }
    r = client.options("/api/0/export", headers=headers)
    assert r.status_code == 403
