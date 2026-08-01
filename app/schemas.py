from datetime import datetime

from pydantic import BaseModel, ConfigDict


class KeyCreate(BaseModel):
    expires_in_days: int | None = None
    max_uses: int = 1

class KeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    status: str
    created_at: datetime
    expires_at: datetime | None
    max_uses: int
    used_uses: int

class KeyListResponse(BaseModel):
    items: list[KeyResponse]
    total: int
    limit: int
    offset: int

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class CheckRequest(BaseModel):
    key: str

class CheckResponse(BaseModel):
    valid: bool
    status: str
    reason: str | None = None
    remaining_uses: int | None = None

