from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import schemas, signing
from ..auth import verify_admin
from ..database import get_db
from ..keygen import generate_key
from ..models import LicenseKey
from ..secrets import load_public_key, load_seed, seed_problem

router = APIRouter(prefix="/api/keys", tags=["keys"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@router.post("", response_model=schemas.KeyResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_admin)])
def create_key(payload: schemas.KeyCreate, db: Session = Depends(get_db)):
    expires_at = None
    if payload.expires_in_days is not None:
        expires_at = utcnow() + timedelta(days=payload.expires_in_days)

    for _ in range(5):
        db_key = LicenseKey(
            key=generate_key(),
            kind="random",
            expires_at=expires_at,
            max_uses=payload.max_uses,
        )
        db.add(db_key)
        try:
            db.commit()
            db.refresh(db_key)
            return db_key
        except IntegrityError:
            db.rollback()
    raise HTTPException(status_code=500, detail="Could not generate a unique key")


@router.get("", response_model=schemas.KeyListResponse, dependencies=[Depends(verify_admin)])
def list_keys(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    # Optional filter so the signed-key page can show only its own keys. The
    # count has to be filtered too, or pagination would report a total that
    # includes rows the caller cannot see on any page.
    kind: str | None = Query(None, pattern="^(random|signed)$"),
    db: Session = Depends(get_db),
):
    count_query = select(func.count()).select_from(LicenseKey)
    items_query = select(LicenseKey)
    if kind:
        count_query = count_query.where(LicenseKey.kind == kind)
        items_query = items_query.where(LicenseKey.kind == kind)

    total = db.scalar(count_query)
    items = db.scalars(
        items_query
        .order_by(LicenseKey.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return schemas.KeyListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/check", response_model=schemas.CheckResponse)
def check_key(payload: schemas.CheckRequest, db: Session = Depends(get_db)):
    # Signed keys are self-contained and verified by the app offline. They must
    # never be validated here: /check consumes a use from `used_uses`, which
    # means one activation attempt *ever* -- pointing a signed key at it would
    # burn the key on a reinstall. Send signed keys to /api/keys/verify.
    if payload.key.strip().upper().startswith(signing.KEY_VERSION + "-"):
        return schemas.CheckResponse(
            valid=False,
            status="invalid",
            reason="This is a signed key; verify it with /api/keys/verify",
        )

    db_key = db.scalar(select(LicenseKey).where(LicenseKey.key == payload.key))
    if db_key is None:
        return schemas.CheckResponse(valid=False, status="invalid", reason="Key not found")

    if db_key.status != "active":
        return schemas.CheckResponse(valid=False, status=db_key.status, reason="Key is revoked")

    if db_key.expires_at and db_key.expires_at < utcnow():
        return schemas.CheckResponse(valid=False, status="expired", reason="Key has expired")

    if db_key.used_uses >= db_key.max_uses:
        return schemas.CheckResponse(valid=False, status="no_uses_left", reason="No uses remaining")

    db_key.used_uses += 1
    db.commit()
    return schemas.CheckResponse(
        valid=True,
        status="valid",
        remaining_uses=db_key.max_uses - db_key.used_uses,
    )


@router.post("/sign", response_model=schemas.SignResponse,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(verify_admin)])
def sign_key(payload: schemas.SignRequest, db: Session = Depends(get_db)):
    """Issue a signed, machine-bound product key. Admin only.

    The key is self-contained: everything needed to verify it is inside it, and
    the app checks it offline. This row is the record of what was issued.
    """
    problem = seed_problem()
    if problem:
        raise HTTPException(status_code=503,
                            detail=f"Signing is unavailable: {problem}")
    seed = load_seed()

    clinic = (payload.clinic or "").strip()
    if not clinic:
        raise HTTPException(status_code=422, detail="clinic is required")
    serial = (payload.serial or "").strip()
    if not serial:
        raise HTTPException(status_code=422, detail="serial is required")

    machine = signing.normalise_machine_code(payload.machine_code or "")
    if machine and not signing.machine_code_is_well_formed(machine):
        raise HTTPException(
            status_code=422,
            detail=("machine_code is not well formed. It should be 16 "
                    "characters in groups of four, e.g. 3ARN-47PE-L5RN-WPVU. "
                    "Ask the customer to read it from their activation screen."),
        )

    try:
        key = signing.make_key(seed, clinic, serial, machine)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Self-check before storing: a key that fails its own verification is worse
    # than an error, because it is sent to a customer and fails there instead.
    public = load_public_key()
    if public and not signing.verify_key(key, public, expected_machine=machine or None):
        raise HTTPException(
            status_code=500,
            detail=("The issued key failed self-verification. The signing seed "
                    "and the configured public key disagree -- run the "
                    "matching check on the vendor machine."),
        )

    parsed = signing.parse_key(key)
    db_key = LicenseKey(
        key=key,
        kind="signed",
        status="active",
        clinic=clinic,
        serial=serial,
        machine_code=machine or None,
        # max_uses is meaningless for a signed key: it is verified offline and
        # never consumes a use. Left at 0/0 so the numbers do not imply a
        # counter that is actually being tracked.
        max_uses=0,
        used_uses=0,
    )
    db.add(db_key)
    try:
        db.commit()
        db.refresh(db_key)
    except IntegrityError:
        db.rollback()
        # The same clinic+serial+machine on the same day produces the same key
        # bytes (Ed25519 is deterministic). Reporting the existing key is more
        # useful than an error, and is what a retry after a dropped response
        # should see.
        existing = db.scalar(select(LicenseKey).where(LicenseKey.key == key))
        if existing is not None:
            return schemas.SignResponse(
                key=existing.key, clinic=clinic, serial=serial,
                machine_code=signing.format_machine_code(machine) if machine else "",
                machine_bound=bool(machine), issued=parsed["issued"],
            )
        raise HTTPException(status_code=500, detail="Could not store the key")

    return schemas.SignResponse(
        key=key,
        clinic=clinic,
        serial=serial,
        machine_code=signing.format_machine_code(machine) if machine else "",
        machine_bound=bool(machine),
        issued=parsed["issued"],
    )


@router.post("/verify", response_model=schemas.VerifyResponse)
def verify_signed_key(payload: schemas.VerifyRequest):
    """Verify a signed key. Public, like /check, but does not consume anything.

    Deliberately separate from /check: verification here is pure cryptography
    against the vendor public key and never touches the database. It exists so
    the dashboard (and a support person) can confirm a key is genuine and
    correctly bound without activating anything.
    """
    public = load_public_key()
    if public is None:
        raise HTTPException(
            status_code=503,
            detail="Verification is unavailable: no signing seed or public key "
                   "is configured on this server.",
        )

    machine = None
    if payload.machine_code:
        machine = signing.normalise_machine_code(payload.machine_code)

    parsed = signing.verify_key(payload.key, public, expected_machine=machine)
    if parsed is None:
        # Say which kind of "no" this is, because the two need different
        # follow-up: a key for another machine is a reissue, a key that does
        # not verify at all is a forgery or a typo.
        unbound = signing.verify_key(payload.key, public)
        if unbound is not None and machine:
            bound_display = (signing.format_machine_code(unbound["machine"])
                             if unbound["machine"] else "site-wide")
            return schemas.VerifyResponse(
                valid=False,
                reason=("This key is genuine but was issued for a different "
                        f"machine ({bound_display}), not "
                        f"{signing.format_machine_code(machine)}."),
                clinic=unbound["clinic_name"],
                serial=unbound["serial"],
                issued=unbound["issued"],
                machine_code=signing.format_machine_code(unbound["machine"])
                if unbound["machine"] else "",
                machine_bound=bool(unbound["machine"]),
            )
        return schemas.VerifyResponse(valid=False, reason="Key is not valid")

    return schemas.VerifyResponse(
        valid=True,
        clinic=parsed["clinic_name"],
        serial=parsed["serial"],
        issued=parsed["issued"],
        machine_code=signing.format_machine_code(parsed["machine"])
        if parsed["machine"] else "",
        machine_bound=bool(parsed["machine"]),
    )


@router.get("/{key}", response_model=schemas.KeyResponse, dependencies=[Depends(verify_admin)])
def get_key(key: str, db: Session = Depends(get_db)):
    db_key = db.scalar(select(LicenseKey).where(LicenseKey.key == key))
    if db_key is None:
        raise HTTPException(status_code=404, detail="Key not found")
    return db_key


@router.post("/{key}/revoke", response_model=schemas.KeyResponse, dependencies=[Depends(verify_admin)])
def revoke_key(key: str, db: Session = Depends(get_db)):
    db_key = db.scalar(select(LicenseKey).where(LicenseKey.key == key))
    if db_key is None:
        raise HTTPException(status_code=404, detail="Key not found")
    db_key.status = "revoked"
    db.commit()
    db.refresh(db_key)
    return db_key


@router.post("/{key}/unrevoke", response_model=schemas.KeyResponse, dependencies=[Depends(verify_admin)])
def unrevoke_key(key: str, db: Session = Depends(get_db)):
    """Undo a revoke.

    Revoking is a bookkeeping flag here, not a remote switch: the app verifies
    keys offline and never learns that a key was revoked. That cuts both ways
    -- revoking does not disable an installed key, and un-revoking cannot
    resurrect anything either. Both actions only change this record, which is
    exactly why a mis-click should be undoable.
    """
    db_key = db.scalar(select(LicenseKey).where(LicenseKey.key == key))
    if db_key is None:
        raise HTTPException(status_code=404, detail="Key not found")
    db_key.status = "active"
    db.commit()
    db.refresh(db_key)
    return db_key