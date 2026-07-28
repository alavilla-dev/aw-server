"""
Endpoint scoping for the moz-extension:// CORS wildcard.

Firefox assigns every extension its own random origin, so aw-server uses
``moz-extension://*`` to allow aw-watcher-web without knowing the ID in advance.
That wildcard also permits every other installed extension to reach the full API —
including ``/api/0/export``, ``/api/0/import``, queries, and settings — with no
host permission and therefore no install-time browser prompt naming ActivityWatch.

This module registers a ``before_request`` hook that restricts wildcard-matched
extension origins to the three endpoints aw-watcher-web actually needs:

  GET  /api/0/info                                  — hostname/version detection
  POST /api/0/buckets/aw-watcher-web-<id>           — ensure its bucket exists
  POST /api/0/buckets/aw-watcher-web-<id>/heartbeat — heartbeat recording

All other paths return 403 before the handler executes. flask-cors CORS headers are
still added by the after_request hook, but the 403 status prevents JavaScript from
treating the response as a successful cross-origin fetch (and more importantly, the
server side never processes the request).

User-configured origins (``cors_origins`` / ``cors_regex`` in config) are exempted:
those are explicit opt-ins by the server owner, unlike the built-in wildcard.

Path matching uses split segments rather than the raw path string to avoid
percent-encoding bypasses — the same bug class as aw-server-rust#588 and #636.

See also: ActivityWatch/aw-server-rust#637 (the Rust sibling of this fix).
"""

import logging
import re
from typing import List, Optional

from flask import Flask, abort, request

logger = logging.getLogger(__name__)

_EXTENSION_SCHEME = "moz-extension://"


def register(app: Flask, user_origins: List[str]) -> None:
    """Register the extension CORS scope hook on *app*.

    *user_origins* — origins the user configured explicitly (captured before
    the built-in ``moz-extension://*`` wildcard is appended).  These are
    explicit opt-ins and bypass the scope narrowing.
    """

    @app.before_request
    def _restrict_extension_cors() -> Optional[object]:
        origin = request.headers.get("Origin", "")
        if not origin.lower().startswith(_EXTENSION_SCHEME):
            return None  # not a moz-extension origin — let flask-cors handle it

        # flask-cors 4 treats strings containing regex metacharacters as regular
        # expressions and otherwise compares them case-insensitively. Keep this
        # exemption consistent with that contract.
        for pattern in user_origins:
            if _matches_configured_origin(origin, pattern):
                return None

        segments = [s for s in request.path.split("/") if s]
        if _is_allowed(request.method, segments):
            return None

        abort(403)


def _matches_configured_origin(origin: str, pattern: str) -> bool:
    """Match an origin using flask-cors 4's configured-origin semantics."""
    regex_chars = "*\\]?$^[()"
    if any(char in pattern for char in regex_chars):
        try:
            return re.match(pattern, origin, flags=re.IGNORECASE) is not None
        except re.error:
            return False
    return origin.lower() == pattern.lower()


def _is_allowed(method: str, segments: List[str]) -> bool:
    """Return True if *method* + *segments* is a path aw-watcher-web actually uses.

    For OPTIONS preflights the path is checked against the set of allowed paths
    (not the Access-Control-Request-Method header) to keep the logic simple while
    still blocking preflights for disallowed paths such as ``/api/0/export``.
    """
    if method == "OPTIONS":
        return _is_allowed_path(segments)

    # GET /api/0/info
    if method == "GET" and segments == ["api", "0", "info"]:
        return True

    # POST /api/0/buckets/aw-watcher-web-<id>
    if (
        method == "POST"
        and len(segments) == 4
        and segments[:3] == ["api", "0", "buckets"]
        and segments[3].startswith("aw-watcher-web-")
    ):
        return True

    # POST /api/0/buckets/aw-watcher-web-<id>/heartbeat
    if (
        method == "POST"
        and len(segments) == 5
        and segments[:3] == ["api", "0", "buckets"]
        and segments[3].startswith("aw-watcher-web-")
        and segments[4] == "heartbeat"
    ):
        return True

    return False


def _is_allowed_path(segments: List[str]) -> bool:
    """Return True if *segments* is on any allowed endpoint (for OPTIONS checks)."""
    if segments == ["api", "0", "info"]:
        return True
    if (
        len(segments) == 4
        and segments[:3] == ["api", "0", "buckets"]
        and segments[3].startswith("aw-watcher-web-")
    ):
        return True
    if (
        len(segments) == 5
        and segments[:3] == ["api", "0", "buckets"]
        and segments[3].startswith("aw-watcher-web-")
        and segments[4] == "heartbeat"
    ):
        return True
    return False
