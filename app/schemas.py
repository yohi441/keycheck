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
    # Present for signed keys; defaulted so existing random keys keep working.
    kind: str = "random"
    clinic: str | None = None
    serial: str | None = None
    machine_code: str | None = None
    activated_at: datetime | None = None

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


# --------------------------------------------------------------------------
# Signed, machine-bound keys
# --------------------------------------------------------------------------

class SignRequest(BaseModel):
    """Issue a signed CLN1- key.

    `machine_code` is the code shown on the customer's activation screen. Omit
    it (or send an empty string) for a site-wide key that activates any
    machine -- a break-glass option, not the normal case.
    """
    clinic: str
    serial: str
    machine_code: str = ""


class SignResponse(BaseModel):
    key: str
    clinic: str
    serial: str
    machine_code: str
    # False when the key is site-wide. Stated explicitly so a caller cannot
    # mistake an unbound key for a bound one.
    machine_bound: bool
    issued: str


class VerifyRequest(BaseModel):
    """Verify a signed key, optionally against a machine code."""
    key: str
    machine_code: str | None = None


class VerifyResponse(BaseModel):
    valid: bool
    reason: str | None = None
    clinic: str | None = None
    serial: str | None = None
    issued: str | None = None
    machine_code: str | None = None
    machine_bound: bool | None = None

