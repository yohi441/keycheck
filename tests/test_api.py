import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

KEY_PATTERN = re.compile(r"^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$")
ADMIN_TOKEN = "dev-secret-change-me"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def create_key(client, payload=None):
    return client.post("/api/keys", json=payload or {}, headers=AUTH)


@pytest.fixture()
def client():
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


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Welcome to the KeyCheck API!"}


def test_create_key_defaults(client):
    resp = create_key(client)
    assert resp.status_code == 201
    data = resp.json()
    assert KEY_PATTERN.match(data["key"])
    assert data["status"] == "active"
    assert data["expires_at"] is None
    assert data["max_uses"] == 1
    assert data["used_uses"] == 0


def test_create_key_with_options(client):
    resp = create_key(client, {"expires_in_days": 30, "max_uses": 5})
    assert resp.status_code == 201
    data = resp.json()
    assert data["expires_at"] is not None
    assert data["max_uses"] == 5


def test_create_key_requires_auth(client):
    assert client.post("/api/keys", json={}).status_code == 401
    assert client.post("/api/keys", json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_check_valid_key(client):
    key = create_key(client, {"max_uses": 3}).json()["key"]
    resp = client.post("/api/keys/check", json={"key": key})
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": True,
        "status": "valid",
        "reason": None,
        "remaining_uses": 2,
    }


def test_check_is_public(client):
    resp = client.post("/api/keys/check", json={"key": "AAAA-BBBB-CCCC-DDDD"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "invalid"


def test_check_consumes_uses(client):
    key = create_key(client, {"max_uses": 1}).json()["key"]
    assert client.post("/api/keys/check", json={"key": key}).json()["valid"] is True
    resp = client.post("/api/keys/check", json={"key": key})
    assert resp.json()["valid"] is False
    assert resp.json()["status"] == "no_uses_left"


def test_check_expired_key(client):
    key = create_key(client, {"expires_in_days": -1}).json()["key"]
    resp = client.post("/api/keys/check", json={"key": key})
    assert resp.json()["valid"] is False
    assert resp.json()["status"] == "expired"


def test_check_revoked_key(client):
    key = create_key(client).json()["key"]
    client.post(f"/api/keys/{key}/revoke", headers=AUTH)
    resp = client.post("/api/keys/check", json={"key": key})
    assert resp.json()["valid"] is False
    assert resp.json()["status"] == "revoked"


def test_check_unknown_key(client):
    resp = client.post("/api/keys/check", json={"key": "AAAA-BBBB-CCCC-DDDD"})
    assert resp.json()["valid"] is False
    assert resp.json()["status"] == "invalid"


def test_list_keys(client):
    create_key(client)
    create_key(client)
    resp = client.get("/api/keys", headers=AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    assert body["limit"] == 50
    assert body["offset"] == 0


def test_list_keys_pagination(client):
    for i in range(5):
        create_key(client)
    page1 = client.get("/api/keys", params={"limit": 2, "offset": 0}, headers=AUTH).json()
    page2 = client.get("/api/keys", params={"limit": 2, "offset": 2}, headers=AUTH).json()
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2
    assert [k["key"] for k in page1["items"]] != [k["key"] for k in page2["items"]]


def test_list_keys_requires_auth(client):
    assert client.get("/api/keys").status_code == 401


def test_get_key(client):
    key = create_key(client).json()["key"]
    resp = client.get(f"/api/keys/{key}", headers=AUTH)
    assert resp.status_code == 200
    assert resp.json()["key"] == key


def test_get_key_requires_auth(client):
    assert client.get("/api/keys/AAAA-BBBB-CCCC-DDDD").status_code == 401


def test_get_key_not_found(client):
    resp = client.get("/api/keys/AAAA-BBBB-CCCC-DDDD", headers=AUTH)
    assert resp.status_code == 404


def test_revoke_key(client):
    key = create_key(client).json()["key"]
    resp = client.post(f"/api/keys/{key}/revoke", headers=AUTH)
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


def test_revoke_key_requires_auth(client):
    resp = client.post("/api/keys/AAAA-BBBB-CCCC-DDDD/revoke")
    assert resp.status_code == 401


def test_login_success(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"]
    assert data["expires_in"] == 3600


def test_login_wrong_password(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "admin"})
    assert resp.status_code == 401


def test_jwt_token_grants_admin_access(client):
    token = client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).json()[
        "access_token"
    ]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post("/api/keys", json={"max_uses": 2}, headers=headers)
    assert resp.status_code == 201
    key = resp.json()["key"]
    assert client.get("/api/keys", headers=headers).status_code == 200
    assert client.get(f"/api/keys/{key}", headers=headers).status_code == 200
