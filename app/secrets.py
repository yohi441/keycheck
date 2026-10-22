"""Vendor signing seed: loading and validation.

The seed is the Ed25519 private key that mints every product key. It is the
single most sensitive value this service holds:

  * Lose it and no further keys can be issued for the current build. Every
    customer would need a rebuilt app with a new public key.
  * Leak it and anyone can mint keys that the app will happily accept.

It is the SAME seed that `tools/issue_key.py` uses on the vendor's machine,
which lives at `%LOCALAPPDATA%\\ClinicManager-keys\\vendor.key`. On the server
it is supplied through `KEYCHECK_LICENSE_SEED` (64 hex characters) in `.env`.

Nothing here reads from the filesystem: on a server the value belongs in the
environment/`.env`, which is already gitignored. `TOOLS`-style key files have
no place in a deployed service.
"""

import os

SEED_ENV = "KEYCHECK_LICENSE_SEED"
PUBLIC_KEY_ENV = "KEYCHECK_LICENSE_PUBLIC_KEY"


def load_seed():
    """Return the 32-byte signing seed, or None when it is not configured.

    Returns None rather than raising so the service can still start and serve
    checking/listing; only the signing endpoint refuses. A service that will
    not boot because a key is missing is harder to diagnose than one that
    boots and says which endpoint is unavailable.
    """
    raw = os.getenv(SEED_ENV, "").strip()
    if not raw:
        return None
    # Tolerate the hex being pasted with whitespace/newlines, exactly as a key
    # would be.
    raw = "".join(raw.split())
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(seed) != 32:
        return None
    return seed


def seed_problem():
    """A human-readable reason the seed is unusable, or None when it is fine."""
    raw = os.getenv(SEED_ENV, "").strip()
    if not raw:
        return f"{SEED_ENV} is not set"
    cleaned = "".join(raw.split())
    try:
        seed = bytes.fromhex(cleaned)
    except ValueError:
        return f"{SEED_ENV} is not valid hex"
    if len(seed) != 32:
        return (f"{SEED_ENV} must be 32 bytes (64 hex characters), "
                f"got {len(seed)}")
    return None


def load_public_key():
    """The public key to report and to self-check against, as raw bytes.

    Derived from the seed when not set explicitly, so a coherent deployment
    cannot report a public key that disagrees with what it signs. An explicit
    `KEYCHECK_LICENSE_PUBLIC_KEY` is honoured so the service can be pinned to
    the value baked into the app and *detect* a seed mismatch.
    """
    from . import signing

    explicit = os.getenv(PUBLIC_KEY_ENV, "").strip()
    if explicit:
        try:
            return bytes.fromhex(explicit)
        except ValueError:
            return None
    seed = load_seed()
    if seed is None:
        return None
    return signing.ed25519_public_key(seed)


def public_key_hex():
    key = load_public_key()
    return key.hex() if key else None
