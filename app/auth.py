import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

load_dotenv()

security = HTTPBearer()

JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_TTL_MINUTES = 60


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def get_admin_token() -> str:
    return _required_env("KEYCHECK_ADMIN_TOKEN")


def get_admin_credentials() -> tuple[str, str]:
    return _required_env("KEYCHECK_ADMIN_USER"), _required_env("KEYCHECK_ADMIN_PASSWORD")


def get_jwt_secret() -> str:
    return _required_env("KEYCHECK_JWT_SECRET")


def get_jwt_ttl() -> timedelta:
    minutes = int(os.getenv("KEYCHECK_JWT_EXPIRES_MINUTES", DEFAULT_TOKEN_TTL_MINUTES))
    return timedelta(minutes=minutes)


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + get_jwt_ttl(),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token == get_admin_token():
        return "static-admin"
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload.get("sub")
