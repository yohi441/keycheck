from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class LicenseKey(Base):
    __tablename__ = "license_keys"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    key: Mapped[str] = mapped_column(String(19), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(10), default="active")  # active | revoked
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    used_uses: Mapped[int] = mapped_column(Integer, default=0)