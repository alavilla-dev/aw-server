"""Multi-user request scoping for CEPEM Watch.

Isolation strategy (see MULTIUSER_DESIGN.md): a single database, with every
bucket transparently namespaced by ``<username>/`` for the authenticated user.
Clients (watchers, web UI) never see the prefix — it is added on the way in and
stripped on the way out by ``ScopedDatastore``, which wraps the real Datastore.

Scoping at the datastore layer means the REST API, the query engine (query2) and
export/import all stay within the caller's namespace with no per-endpoint changes.
"""
import logging
from typing import Dict

from flask import Response, g, jsonify, request

from .auth import PREFIX_SEP, verify_token

logger = logging.getLogger(__name__)


class ScopedBucket:
    """Wraps a Bucket so its metadata reports the unprefixed bucket id.

    Everything else (get/insert/delete/...) is proxied unchanged to the real
    bucket, which still operates on the internally-prefixed id.
    """

    def __init__(self, real_bucket, prefix: str):
        self._b = real_bucket
        self._prefix = prefix

    def metadata(self) -> dict:
        m = dict(self._b.metadata())
        bid = m.get("id")
        if isinstance(bid, str) and bid.startswith(self._prefix):
            m["id"] = bid[len(self._prefix) :]
        return m

    def __getattr__(self, name):
        return getattr(self._b, name)


def _strip_meta(meta: dict, prefix: str) -> dict:
    bid = meta.get("id")
    if isinstance(bid, str) and bid.startswith(prefix):
        meta = dict(meta)
        meta["id"] = bid[len(prefix) :]
    return meta


class ScopedDatastore:
    """A per-request view over the real Datastore, namespaced to one user.

    Only the surface used by ServerAPI and aw_query is implemented; anything that
    would bypass the namespace is intentionally absent.
    """

    def __init__(self, real, prefix: str):
        self._real = real
        self._prefix = prefix

    def _int(self, bucket_id: str) -> str:
        return self._prefix + bucket_id

    def buckets(self) -> Dict[str, dict]:
        plen = len(self._prefix)
        return {
            bid[plen:]: _strip_meta(meta, self._prefix)
            for bid, meta in self._real.buckets().items()
            if bid.startswith(self._prefix)
        }

    def __getitem__(self, bucket_id: str):
        return ScopedBucket(self._real[self._int(bucket_id)], self._prefix)

    def create_bucket(self, bucket_id: str, **kwargs):
        return self._real.create_bucket(self._int(bucket_id), **kwargs)

    def update_bucket(self, bucket_id: str, **kwargs):
        return self._real.update_bucket(self._int(bucket_id), **kwargs)

    def delete_bucket(self, bucket_id: str, **kwargs):
        return self._real.delete_bucket(self._int(bucket_id), **kwargs)


def prefix_for(username: str) -> str:
    return f"{username}{PREFIX_SEP}"


def make_auth_before_request(testing: bool):
    """Build a Flask before_request handler enforcing per-user token auth on /api/*."""

    def _before_request():
        # Only the JSON API is protected; static dashboard assets load freely so the
        # web UI can render its token-login screen. CORS preflight must pass through.
        if request.method == "OPTIONS":
            return None
        path = request.path or ""
        if not path.startswith("/api/"):
            return None

        auth = request.headers.get("Authorization", "")
        token = ""
        if auth.startswith("Bearer "):
            token = auth[len("Bearer ") :].strip()
        # Fallback: allow ?token= for requests that can't set headers (e.g. <img>
        # tags loading screenshots).
        if not token:
            token = (request.args.get("token") or "").strip()

        identity = verify_token(token, testing=testing)
        if identity is None:
            resp: Response = jsonify(
                {"error": "unauthorized", "message": "Valid API token required"}
            )
            resp.status_code = 401
            resp.headers["WWW-Authenticate"] = "Bearer"
            return resp

        g.aw_user = identity["username"]
        g.aw_role = identity["role"]
        g.aw_prefix = prefix_for(identity["username"])

        # Admin "view as": an admin may scope the request to another user's data
        # by sending X-AW-As-User. Non-admins cannot impersonate.
        if identity["role"] == "admin":
            target = request.headers.get("X-AW-As-User", "").strip()
            if target:
                from .auth import load_users

                if target in load_users(testing=testing):
                    g.aw_user = target
                    g.aw_prefix = prefix_for(target)
        return None

    return _before_request
