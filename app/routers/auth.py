import secrets

from fastapi import APIRouter, HTTPException, status

from .. import schemas
from ..auth import create_access_token, get_admin_credentials, get_jwt_ttl

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=schemas.TokenResponse)
def login(payload: schemas.LoginRequest):
    username, password = get_admin_credentials()
    if not secrets.compare_digest(payload.username, username) or not secrets.compare_digest(
        payload.password, password
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return schemas.TokenResponse(
        access_token=create_access_token(payload.username),
        expires_in=int(get_jwt_ttl().total_seconds()),
    )
