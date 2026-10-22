from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class LicenseKey(Base):
    __tablename__ = "license_keys"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    # Holds either format:
    #   random  AAAA-BBBB-CCCC-DDDD  (19 chars)
    #   signed  CLN1-<payload>-<sig> (~180 chars)
    # Widened from String(19) to fit signed keys. SQLite ignores the length
    # anyway, but the type should say what it means. `unique` still holds for
    # both, which is what makes the lookup below safe.
    key: Mapped[str] = mapped_column(Text, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(10), default="active")  # active | revoked
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    used_uses: Mapped[int] = mapped_column(Integer, default=0)

    # --- Signed (machine-bound) keys -------------------------------------
    # A row now describes either kind of key:
    #
    #   kind='random'  the original opaque AAAA-BBBB-CCCC-DDDD keys. Validated
    #                  by looking the row up through /api/keys/check, which
    #                  consumes a use. Behaviour unchanged.
    #   kind='signed'  a self-contained CLN1-... key. The app verifies it
    #                  offline against the vendor public key; this row is the
    #                  *record* of what was issued, not what makes it valid.
    #
    # Both live in one table so the dashboard can list them together, but the
    # two code paths never mix: /check only ever sees random keys, and the
    # signed endpoints never touch used_uses.
    #
    # Existing rows predate these columns and are all the original kind, so a
    # server default of 'random' backfills them correctly.
    kind: Mapped[str] = mapped_column(String(10), default="random", server_default="random")

    clinic: Mapped[str | None] = mapped_column(String(200), nullable=True)
    serial: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Normalised machine code (upper case, no dashes). NULL or '' means the key
    # is site-wide and activates any machine.
    machine_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # When a customer's app first reported the key as activated. Only set if
    # the app ever phones home; nothing requires it, and the app works offline.
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)