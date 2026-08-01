from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import verify_admin
from ..database import get_db
from ..keygen import generate_key
from ..models import LicenseKey

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
    db: Session = Depends(get_db),
):
    total = db.scalar(select(func.count()).select_from(LicenseKey))
    items = db.scalars(
        select(LicenseKey)
        .order_by(LicenseKey.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return schemas.KeyListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/check", response_model=schemas.CheckResponse)
def check_key(payload: schemas.CheckRequest, db: Session = Depends(get_db)):
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