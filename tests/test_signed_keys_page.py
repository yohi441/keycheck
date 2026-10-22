"""Tests for the Clinic Manager key page and the `kind` filter it relies on.

The page exists so that issuing a signed, machine-bound key is a separate job
from the original random-key workflow. Two things therefore have to hold:

  * the page is served and is reachable from the dashboard,
  * `/api/keys?kind=signed` returns only signed keys, with a total that matches
    (otherwise pagination would report rows that are never shown).

The filter is additive: omitting `kind` must behave exactly as it did before,
which the existing dashboard depends on.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

ADMIN_TOKEN = "dev-secret-change-me"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

TEST_SEED_HEX = "1f" * 32
MACHINE = "3ARN-47PE-L5RN-WPVU"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("KEYCHECK_LICENSE_SEED", TEST_SEED_HEX)
    monkeypatch.delenv("KEYCHECK_LICENSE_PUBLIC_KEY", raising=False)

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        session = TestSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def make_random(client, count=1):
    for _ in range(count):
        resp = client.post("/api/keys", json={"max_uses": 1}, headers=AUTH)
        assert resp.status_code == 201


def make_signed(client, count=1, machine=MACHINE):
    keys = []
    for index in range(count):
        resp = client.post(
            "/api/keys/sign",
            json={"clinic": "John's Eye Clinic", "serial": str(100 + index),
                  "machine_code": machine},
            headers=AUTH,
        )
        assert resp.status_code == 201, resp.text
        keys.append(resp.json()["key"])
    return keys


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def test_signed_keys_page_is_served(client):
    resp = client.get("/signed-keys")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert "Clinic Manager Keys" in body
    # The page must talk to the signed endpoints, not the random ones.
    assert "/api/keys/sign" in body
    assert "kind=signed" in body


def test_dashboard_links_to_the_page(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert 'href="/signed-keys"' in resp.text


def test_page_can_reveal_and_copy_a_stored_key(client):
    """A refresh must not strand a key: every row keeps its full text.

    This regression happened for real -- the "Issued key" card is browser
    session state, so after a refresh the only copy of the key was in the
    database with no way to read it back from the page.
    """
    body = client.get("/signed-keys").text
    assert "Show key" in body
    assert "toggleKey" in body
    assert "copyValue(k.key)" in body
    # The expanded panel renders the whole key, not the truncated cell.
    assert "x-text=\"k.key\"" in body


def test_page_can_undo_a_revoke(client):
    body = client.get("/signed-keys").text
    assert "Un-revoke" in body
    assert "/unrevoke" in body


def test_page_does_not_issue_random_keys(client):
    """Guard against someone pointing the new page at the old endpoint.

    A random key looks harmless but the clinic app rejects it, so this is a
    mistake worth pinning down in a test rather than in production.
    """
    body = client.get("/signed-keys").text
    assert "/api/keys/check" not in body
    # "/api/keys/sign" contains "/api/keys" -- assert the create endpoint is
    # not used with POST, which is how random keys are made.
    assert "fetch('/api/keys'" not in body


# --------------------------------------------------------------------------
# The kind filter
# --------------------------------------------------------------------------

def test_kind_signed_returns_only_signed(client):
    make_random(client, 2)
    make_signed(client, 2)

    data = client.get("/api/keys?kind=signed", headers=AUTH).json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert all(item["kind"] == "signed" for item in data["items"])


def test_kind_random_returns_only_random(client):
    make_random(client, 2)
    make_signed(client, 2)

    data = client.get("/api/keys?kind=random", headers=AUTH).json()
    assert data["total"] == 2
    assert all(item["kind"] == "random" for item in data["items"])


def test_omitting_kind_returns_both(client):
    """Backwards compatibility: the existing dashboard sends no `kind`."""
    make_random(client, 2)
    make_signed(client, 2)

    data = client.get("/api/keys", headers=AUTH).json()
    assert data["total"] == 4
    assert {item["kind"] for item in data["items"]} == {"random", "signed"}


def test_kind_filter_total_matches_pages(client):
    """`total` must describe the filtered set, not the whole table.

    With 3 signed and 5 random keys, a page of 2 signed keys has to say "3",
    otherwise the pager offers pages that render empty.
    """
    make_random(client, 5)
    make_signed(client, 3)

    data = client.get("/api/keys?kind=signed&limit=2&offset=0", headers=AUTH).json()
    assert data["total"] == 3
    assert len(data["items"]) == 2

    second = client.get("/api/keys?kind=signed&limit=2&offset=2", headers=AUTH).json()
    assert len(second["items"]) == 1


def test_kind_filter_rejects_unknown_values(client):
    assert client.get("/api/keys?kind=bogus", headers=AUTH).status_code == 422


def test_kind_filter_requires_auth(client):
    assert client.get("/api/keys?kind=signed").status_code == 401


# --------------------------------------------------------------------------
# The exact call the page makes
# --------------------------------------------------------------------------

def test_page_payload_is_accepted(client):
    """Send what the form sends: an untidy machine code, as a customer would."""
    resp = client.post(
        "/api/keys/sign",
        json={"clinic": "John's Eye Clinic", "serial": "0007",
              "machine_code": "3arn 47pe l5rn wpvu"},
        headers=AUTH,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["machine_bound"] is True
    assert data["machine_code"] == MACHINE
