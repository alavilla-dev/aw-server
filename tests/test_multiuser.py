"""Multi-user isolation tests for CEPEM Watch.

Verifies per-user token auth and that bucket namespacing keeps each user's data
fully isolated while remaining transparent (clients use unprefixed bucket ids).
"""
from datetime import datetime, timezone

import pytest

from aw_server import auth
from aw_server.server import AWFlask


@pytest.fixture
def users(monkeypatch):
    store = {
        "alice": {"token_sha256": auth.hash_token("tok-alice"), "role": "user"},
        "bob": {"token_sha256": auth.hash_token("tok-bob"), "role": "user"},
    }
    # verify_token() looks up load_users at call time, so patching here is enough.
    monkeypatch.setattr(auth, "load_users", lambda testing=False: store)
    return store


@pytest.fixture
def client(users):
    app = AWFlask("127.0.0.1", testing=True, multiuser=True)
    return app.test_client()


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _mkbucket(client, bucket_id, token):
    return client.post(
        f"/api/0/buckets/{bucket_id}",
        json={"client": "test", "type": "test", "hostname": "test"},
        headers=_h(token),
    )


def _heartbeat(client, bucket_id, token, data):
    return client.post(
        f"/api/0/buckets/{bucket_id}/heartbeat?pulsetime=1",
        json={
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration": 0,
            "data": data,
        },
        headers=_h(token),
    )


def test_requires_valid_token(client):
    assert client.get("/api/0/buckets/").status_code == 401
    assert client.get("/api/0/buckets/", headers=_h("wrong")).status_code == 401
    assert client.get("/api/0/buckets/", headers=_h("tok-alice")).status_code == 200


def test_bucket_isolation_between_users(client):
    # alice creates a bucket + one event
    assert _mkbucket(client, "b1", "tok-alice").status_code == 200
    assert _heartbeat(client, "b1", "tok-alice", {"app": "alice-app"}).status_code == 200

    # alice sees exactly her bucket, by its unprefixed id
    ra = client.get("/api/0/buckets/", headers=_h("tok-alice"))
    assert ra.status_code == 200
    assert list(ra.json.keys()) == ["b1"]
    # the namespace prefix must be fully transparent: metadata id has no prefix
    assert ra.json["b1"]["id"] == "b1"
    meta = client.get("/api/0/buckets/b1", headers=_h("tok-alice"))
    assert meta.status_code == 200
    assert meta.json["id"] == "b1"

    # bob sees nothing yet
    rb = client.get("/api/0/buckets/", headers=_h("tok-bob"))
    assert rb.status_code == 200
    assert rb.json == {}

    # bob cannot read alice's bucket events (it does not exist in his namespace)
    assert client.get("/api/0/buckets/b1/events", headers=_h("tok-bob")).status_code == 404

    # bob creates his OWN bucket with the same unprefixed id -> isolated
    assert _mkbucket(client, "b1", "tok-bob").status_code == 200
    assert _heartbeat(client, "b1", "tok-bob", {"app": "bob-app-1"}).status_code == 200
    assert _heartbeat(client, "b1", "tok-bob", {"app": "bob-app-2"}).status_code == 200

    # alice still has exactly 1 event with her data; bob has his own events
    ea = client.get("/api/0/buckets/b1/events", headers=_h("tok-alice")).json
    eb = client.get("/api/0/buckets/b1/events", headers=_h("tok-bob")).json
    assert len(ea) == 1
    assert ea[0]["data"] == {"app": "alice-app"}
    assert all(e["data"]["app"].startswith("bob-app") for e in eb)
    assert not any(e["data"] == {"app": "alice-app"} for e in eb)


def test_query_is_scoped(client):
    _mkbucket(client, "b1", "tok-alice")
    _heartbeat(client, "b1", "tok-alice", {"app": "alice-app"})

    q = {
        "query": ['RETURN = query_bucket("b1");'],
        "timeperiods": ["1970-01-01T00:00:00+00:00/2100-01-01T00:00:00+00:00"],
    }
    # alice's query sees her event
    ra = client.post("/api/0/query/", json=q, headers=_h("tok-alice"))
    assert ra.status_code == 200
    assert len(ra.json[0]) == 1

    # bob's identical query references a bucket that doesn't exist in his namespace
    rb = client.post("/api/0/query/", json=q, headers=_h("tok-bob"))
    assert rb.status_code >= 400
