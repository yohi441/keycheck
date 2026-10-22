"""Tests for signed, machine-bound keys: /api/keys/sign and /api/keys/verify.

The property that matters most here is agreement with the clinic-manager app.
A key that verifies here but not there (or vice versa) is a support call, so
the cross-implementation round-trip is tested against the app's own
`core/licensing.py` when it is reachable on the same machine. That test is
skipped (not failed) when the app checkout is not present, so this suite still
runs anywhere.
"""

import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import signing
from app.database import Base, get_db
from app.main import app

ADMIN_TOKEN = "dev-secret-change-me"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# A fixed test seed so keys are reproducible and the tests do not depend on the
# real vendor seed being present in the environment.
TEST_SEED_HEX = "1f" * 32
TEST_SEED = bytes.fromhex(TEST_SEED_HEX)
TEST_PUBLIC = signing.ed25519_public_key(TEST_SEED)

MACHINE = "3ARN-47PE-L5RN-WPVU"
OTHER_MACHINE = "ZZZZ-ZZZZ-ZZZZ-ZZZZ"

CLN_KEY = re.compile(r"^CLN1-[A-Z2-7]+-[A-Z2-7]+$")

# The clinic-manager checkout, if present, for the cross-implementation test.
APP_PATHS = [
    Path(r"C:\Users\yohi\Desktop\clinic-manager"),
    Path.home() / "Desktop" / "clinic-manager",
    Path.home() / "clinic-manager",
]


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


def sign(client, **overrides):
    payload = {"clinic": "John's Eye Clinic", "serial": "0007"}
    payload.update(overrides)
    return client.post("/api/keys/sign", json=payload, headers=AUTH)


# --------------------------------------------------------------------------
# /api/keys/sign
# --------------------------------------------------------------------------

def test_sign_requires_auth(client):
    assert client.post("/api/keys/sign", json={"clinic": "x", "serial": "1"}).status_code == 401
    assert client.post(
        "/api/keys/sign", json={"clinic": "x", "serial": "1"},
        headers={"Authorization": "Bearer wrong"},
    ).status_code == 401


def test_sign_machine_bound_key(client):
    resp = sign(client, machine_code=MACHINE)
    assert resp.status_code == 201
    data = resp.json()
    assert CLN_KEY.match(data["key"])
    assert data["clinic"] == "John's Eye Clinic"
    assert data["serial"] == "0007"
    assert data["machine_bound"] is True
    # Returned in display form, not the normalised internal form.
    assert data["machine_code"] == MACHINE


def test_sign_site_wide_key(client):
    resp = sign(client)
    assert resp.status_code == 201
    data = resp.json()
    assert data["machine_bound"] is False
    assert data["machine_code"] == ""
    # No machine field inside the key.
    assert signing.parse_key(data["key"])["machine"] == ""


def test_sign_requires_clinic_and_serial(client):
    assert client.post("/api/keys/sign", json={"serial": "1"}, headers=AUTH).status_code == 422
    assert client.post("/api/keys/sign", json={"clinic": "x"}, headers=AUTH).status_code == 422
    assert client.post(
        "/api/keys/sign", json={"clinic": "  ", "serial": "1"}, headers=AUTH
    ).status_code == 422


def test_sign_rejects_malformed_machine_code(client):
    # 12 characters -- a plausible typo, and short of a real code.
    resp = sign(client, machine_code="K7F2-9QXM-3B1D")
    assert resp.status_code == 422
    assert "well formed" in resp.json()["detail"]


def test_sign_accepts_untidy_machine_code(client):
    # Lower case, spaces instead of dashes, and a mistyped 0 for Q.
    resp = sign(client, machine_code="3arn 47pe l5rn wpv0")
    assert resp.status_code == 201
    # Stored normalised: 0 -> Q, so the key is bound to ...WPVQ.
    assert resp.json()["machine_bound"] is True
    assert signing.parse_key(resp.json()["key"])["machine"].endswith("WPVQ")


def test_sign_is_deterministic_within_a_day(client):
    """The same request twice yields the same key bytes.

    Ed25519 is deterministic and `issued` is a date, so re-issuing a lost key
    reproduces it. That is a feature: a customer who loses their key can be
    sent the same one again without invalidating anything.
    """
    first = sign(client, machine_code=MACHINE).json()["key"]
    second = sign(client, machine_code=MACHINE).json()["key"]
    assert first == second


def test_sign_stores_a_record(client):
    key = sign(client, machine_code=MACHINE).json()["key"]
    resp = client.get(f"/api/keys/{key}", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["kind"] == "signed"
    assert data["clinic"] == "John's Eye Clinic"
    assert data["serial"] == "0007"
    assert data["machine_code"] == signing.normalise_machine_code(MACHINE)


def test_sign_unavailable_without_seed(client, monkeypatch):
    monkeypatch.delenv("KEYCHECK_LICENSE_SEED", raising=False)
    resp = sign(client, machine_code=MACHINE)
    assert resp.status_code == 503
    assert "not set" in resp.json()["detail"]


def test_sign_rejects_a_mismatched_public_key_pin(client, monkeypatch):
    """An explicitly pinned public key that disagrees with the seed is caught
    at issue time rather than producing keys that will not activate."""
    monkeypatch.setenv("KEYCHECK_LICENSE_PUBLIC_KEY", "ab" * 32)
    resp = sign(client, machine_code=MACHINE)
    assert resp.status_code == 500
    assert "self-verification" in resp.json()["detail"]


# --------------------------------------------------------------------------
# /api/keys/verify
# --------------------------------------------------------------------------

def test_verify_is_public(client):
    key = sign(client, machine_code=MACHINE).json()["key"]
    resp = client.post("/api/keys/verify", json={"key": key, "machine_code": MACHINE})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_verify_reports_fields(client):
    key = sign(client, machine_code=MACHINE).json()["key"]
    data = client.post(
        "/api/keys/verify", json={"key": key, "machine_code": MACHINE}
    ).json()
    assert data["clinic"] == "John's Eye Clinic"
    assert data["serial"] == "0007"
    assert data["machine_bound"] is True
    assert data["issued"]


def test_verify_rejects_wrong_machine_with_a_clear_reason(client):
    key = sign(client, machine_code=MACHINE).json()["key"]
    data = client.post(
        "/api/keys/verify", json={"key": key, "machine_code": OTHER_MACHINE}
    ).json()
    assert data["valid"] is False
    assert "different" in data["reason"]
    # The reason names the machine it *is* for, so the fix is obvious.
    assert signing.format_machine_code(MACHINE) in data["reason"]


def test_verify_rejects_junk(client):
    data = client.post("/api/keys/verify", json={"key": "CLN1-AAAA-BBBB"}).json()
    assert data["valid"] is False
    assert data["reason"] == "Key is not valid"


def test_verify_site_wide_key_anywhere(client):
    key = sign(client).json()["key"]
    for machine in (MACHINE, OTHER_MACHINE, None):
        payload = {"key": key}
        if machine:
            payload["machine_code"] = machine
        assert client.post("/api/keys/verify", json=payload).json()["valid"] is True


def test_verify_signature_only_when_no_machine_given(client):
    key = sign(client, machine_code=MACHINE).json()["key"]
    data = client.post("/api/keys/verify", json={"key": key}).json()
    assert data["valid"] is True
    assert data["machine_bound"] is True


def test_verify_rejects_a_key_from_another_seed(client):
    other = signing.make_key(bytes.fromhex("2a" * 32), "Forged Clinic", "9999", MACHINE)
    data = client.post("/api/keys/verify", json={"key": other}).json()
    assert data["valid"] is False


def test_verify_unavailable_without_seed_or_key(client, monkeypatch):
    monkeypatch.delenv("KEYCHECK_LICENSE_SEED", raising=False)
    monkeypatch.delenv("KEYCHECK_LICENSE_PUBLIC_KEY", raising=False)
    resp = client.post("/api/keys/verify", json={"key": "CLN1-A-B"})
    assert resp.status_code == 503


# --------------------------------------------------------------------------
# The two key systems must not mix
# --------------------------------------------------------------------------

def test_check_refuses_a_signed_key(client):
    key = sign(client, machine_code=MACHINE).json()["key"]
    data = client.post("/api/keys/check", json={"key": key}).json()
    assert data["valid"] is False
    assert "signed" in (data["reason"] or "")


def test_check_still_works_for_random_keys(client):
    """The original flow is untouched."""
    key = client.post("/api/keys", json={"max_uses": 2}, headers=AUTH).json()["key"]
    assert client.post("/api/keys/check", json={"key": key}).json()["valid"] is True


def test_signed_keys_do_not_consume_uses(client):
    """Verifying a signed key repeatedly must never exhaust it.

    This is the reason /check is kept away from signed keys: its counter means
    one activation ever, so a reinstall would burn the key.
    """
    key = sign(client, machine_code=MACHINE).json()["key"]
    for _ in range(5):
        assert client.post(
            "/api/keys/verify", json={"key": key, "machine_code": MACHINE}
        ).json()["valid"] is True
    record = client.get(f"/api/keys/{key}", headers=AUTH).json()
    assert record["used_uses"] == 0


def test_schema_defaults_random_kind_for_existing_rows(client):
    key = client.post("/api/keys", json={}, headers=AUTH).json()["key"]
    assert client.get(f"/api/keys/{key}", headers=AUTH).json()["kind"] == "random"


# --------------------------------------------------------------------------
# Cross-implementation round-trip (the important one)
# --------------------------------------------------------------------------
# KeyCheck's venv has no Django and the app's venv has no FastAPI, so neither
# interpreter can import both sides. The round-trip therefore runs as a
# subprocess under the *app's* interpreter, driven by tools/check_roundtrip.py.
# If the checkout or its venv is not present, the test skips rather than fails:
# the same check is also runnable by hand and is listed in the release steps.

def _app_checkout():
    for path in APP_PATHS:
        if (path / "core" / "licensing.py").exists():
            return path
    return None


def _app_python(app_path):
    candidates = [
        app_path / "env" / "Scripts" / "python.exe",
        app_path / "env" / "bin" / "python",
        app_path / ".venv" / "Scripts" / "python.exe",
        app_path / ".venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


@pytest.fixture()
def cross_repo():
    app_path = _app_checkout()
    if app_path is None:
        pytest.skip("clinic-manager checkout not found; skipping round-trip")
    app_python = _app_python(app_path)
    if app_python is None:
        pytest.skip("clinic-manager venv not found; skipping round-trip")
    return app_path, app_python


def test_cross_implementation_roundtrip(cross_repo):
    """KeyCheck and the app must sign identical bytes and cross-verify.

    This is the test that catches any drift in the signed payload format. It is
    the whole reason `app/signing.py` is a copy rather than a reimplementation.
    """
    import subprocess

    app_path, app_python = cross_repo
    script = Path(__file__).resolve().parent.parent / "tools" / "check_roundtrip.py"
    assert script.exists(), f"missing {script}"

    result = subprocess.run(
        [sys.executable, str(script),
         "--app-path", str(app_path),
         "--app-python", str(app_python)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"round-trip check failed:\n{result.stdout}\n{result.stderr}")
    assert "byte-identical" in result.stdout
