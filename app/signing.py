"""Signed, machine-bound product keys -- the issuer side.

This module is the counterpart to `core/licensing.py` in the clinic-manager
app. The app verifies keys offline; this service *issues* them. For a key to be
accepted, the two must agree exactly on:

  * the payload string that gets signed  -> `_payload_bytes`
  * the JSON body carried inside the key -> `payload_body`
  * the base32 armouring                 -> `_b32encode` / `_b32decode`
  * Ed25519 itself                       -> the block below

Any divergence is silent at issue time and shows up as a rejected key on the
customer's machine, so treat this file and `core/licensing.py` as a matched
pair: change one, change the other, and re-run the round-trip test.

What is signed
--------------
    CLN1|<clinic>|<issued>|<serial>          unbound / site-wide key
    CLN1|<clinic>|<issued>|<serial>|<machine> machine-bound key

The machine field is appended only when non-empty. That matters for
compatibility: a key issued before machine binding existed has no machine
field, and appending an empty one unconditionally would change the signed
bytes and invalidate it for no benefit.

`issued` is part of the signed data but is NOT a validity window -- keys do not
expire. It is a record of when the vendor issued the key.

Ed25519
-------
Implemented in pure Python (RFC 8032), copied from the app so both sides sign
identical bytes. A native `cryptography` wheel would be faster, but the whole
point is that the two implementations are provably the same code.
"""

import base64
import hashlib
import json

# --------------------------------------------------------------------------
# Key format
# --------------------------------------------------------------------------

KEY_VERSION = "CLN1"

# Alias table for hand-typed keys. Base32's alphabet is A-Z plus 2-7, so I, L,
# O and U are themselves valid symbols and must NOT be rewritten -- doing so
# corrupts perfectly good keys. Only the genuinely ambiguous characters are
# normalised: a typed 0 becomes O and a typed 1 becomes I, since 0 and 1 are
# not in the alphabet and so can only be misreadings.
_B32_FIXUP = str.maketrans({"0": "O", "1": "I"})


# --------------------------------------------------------------------------
# Ed25519 (pure Python, RFC 8032) -- byte-identical to the app's copy
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(data):
    return hashlib.sha512(data).digest()


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_By = 4 * _inv(5) % _P
_Bx = _xrecover(_By)
_B = (_Bx % _P, _By % _P, 1, _Bx * _By % _P)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _edwards_double(p):
    return _edwards_add(p, p)


def _scalarmult(p, e):
    if e == 0:
        return (0, 1, 1, 0)
    q = _scalarmult(p, e // 2)
    q = _edwards_double(q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encodepoint(p):
    x, y, z, _ = p
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _decodepoint(s):
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = _P - x
    p = (x, y, 1, x * y % _P)
    if not _isedwards(p):
        raise ValueError("point is not on the curve")
    return p


def _isedwards(p):
    x, y, z, t = p
    return (
        z % _P != 0
        and x * y % _P == z * t % _P
        and (y * y - x * x - z * z - _D * t * t) % _P == 0
    )


def ed25519_public_key(seed):
    """Derive the 32-byte public key from a 32-byte private seed."""
    h = _sha512(seed)
    a = 2 ** 254 + sum(2 ** i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    return _encodepoint(_scalarmult(_B, a))


def ed25519_sign(seed, message):
    """Sign a message with a 32-byte private seed. Returns 64 bytes."""
    h = _sha512(seed)
    a = 2 ** 254 + sum(2 ** i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    pub = _encodepoint(_scalarmult(_B, a))
    r = int.from_bytes(_sha512(h[32:] + message), "little") % _L
    rp = _encodepoint(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(rp + pub + message), "little") % _L
    s = (r + k * a) % _L
    return rp + s.to_bytes(32, "little")


def ed25519_verify(public_key, signature, message):
    """True when `signature` is a valid Ed25519 signature of `message`.

    Never raises: a malformed key or signature is simply not valid.
    """
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a = _decodepoint(public_key)
        r = _decodepoint(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(
            _sha512(signature[:32] + public_key + message), "little") % _L
        return _encodepoint(_scalarmult(_B, s)) == _encodepoint(
            _edwards_add(r, _scalarmult(a, h)))
    except Exception:
        return False


# --------------------------------------------------------------------------
# Payload encoding
# --------------------------------------------------------------------------

def _b32encode(raw):
    """RFC 4648 base32 without padding."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(text):
    # Whitespace is stripped anywhere, not just around the edges: a key pasted
    # from an email routinely arrives wrapped mid-key.
    text = "".join(text.split()).upper().translate(_B32_FIXUP).replace("-", "")
    pad = (-len(text)) % 8
    return base64.b32decode(text + "=" * pad)


def _payload_bytes(clinic_name, issued, serial, machine=""):
    """The exact bytes that are signed.

    Order and separators are part of the format -- changing them invalidates
    every key already issued. This must match `core/licensing._payload_bytes`.
    """
    base = f"{KEY_VERSION}|{clinic_name}|{issued}|{serial}"
    if machine:
        base += f"|{machine}"
    return base.encode("utf-8")


def payload_body(clinic_name, issued, serial, machine=""):
    """The JSON carried inside the key (base32-armoured by `make_key`).

    Separators and key order are fixed so the bytes are reproducible. This must
    match the dict built in `core/licensing.make_key`.
    """
    payload = {"clinic": clinic_name, "issued": issued, "serial": serial}
    if machine:
        payload["machine"] = machine
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


# --------------------------------------------------------------------------
# Machine codes
# --------------------------------------------------------------------------
# Same alphabet and same 4x4 grouping as the app. Kept here so the issuer can
# validate what a customer sends back before it ends up inside a signature:
# a typo'd machine code produces a key that can never activate.

_MACHINE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_MACHINE_GROUPS = 4
_MACHINE_GROUP_LEN = 4


def normalise_machine_code(code):
    """Strip separators and case; fold the four confusable characters.

    This must match `core/licensing.normalise_machine_code`. It is applied
    before signing so the value stored inside the key is always in the same
    shape the app will normalise it into.
    """
    if not isinstance(code, str):
        return ""
    text = "".join(code.split()).upper().replace("-", "")
    text = text.translate(str.maketrans({"I": "J", "O": "P", "0": "Q", "1": "R"}))
    return text


def machine_code_is_well_formed(code):
    """True when `code` looks like a machine code we could have produced.

    Checked after normalisation: 16 characters, all from the alphabet. This is
    deliberately a *shape* check, not a checksum -- the signature is what makes
    a key genuine, and a malformed code here would only ever produce a key that
    fails activation, so catching it at issue time saves a support round-trip.
    """
    text = normalise_machine_code(code)
    return len(text) == 16 and all(c in _MACHINE_ALPHABET for c in text)


def format_machine_code(code):
    """Render a normalised code in the 4x4 display form, e.g. K7F2-9QXM-3B1D."""
    text = normalise_machine_code(code)
    groups = [text[i:i + _MACHINE_GROUP_LEN]
              for i in range(0, len(text), _MACHINE_GROUP_LEN)]
    return "-".join(groups)


# --------------------------------------------------------------------------
# Key making / verification
# --------------------------------------------------------------------------

def make_key(seed, clinic_name, serial, machine="", issued=None):
    """Build a signed product key.

    `issued` defaults to today's date (UTC). It is part of the signature but is
    not a validity window -- keys do not expire.
    """
    clinic_name = (clinic_name or "").strip()
    if not clinic_name:
        raise ValueError("clinic_name is required")
    serial = str(serial).strip()
    if not serial:
        raise ValueError("serial is required")

    machine = normalise_machine_code(machine)
    if machine and not machine_code_is_well_formed(machine):
        raise ValueError("machine is not a well-formed machine code")

    if issued is None:
        from datetime import date
        issued = date.today().isoformat()

    message = _payload_bytes(clinic_name, issued, serial, machine)
    signature = ed25519_sign(seed, message)
    body = payload_body(clinic_name, issued, serial, machine)
    return f"{KEY_VERSION}-{_b32encode(body)}-{_b32encode(signature)}"


def parse_key(key):
    """Split a key into its fields, or return None when it is unparseable."""
    if not isinstance(key, str):
        return None
    cleaned = "".join(key.split())
    parts = cleaned.split("-")
    if len(parts) < 3 or parts[0].upper() != KEY_VERSION:
        return None
    try:
        payload = json.loads(_b32decode(parts[1]).decode("utf-8"))
        signature = _b32decode("".join(parts[2:]))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    clinic_name = payload.get("clinic")
    issued = payload.get("issued")
    serial = payload.get("serial")
    machine = payload.get("machine", "")
    if not isinstance(clinic_name, str) or not clinic_name.strip():
        return None
    if not isinstance(issued, str) or not isinstance(serial, str):
        return None
    if not isinstance(machine, str):
        return None
    machine = normalise_machine_code(machine)
    return {
        "clinic_name": clinic_name.strip(),
        "issued": issued,
        "serial": serial,
        "machine": machine,
        "signature": signature,
        "message": _payload_bytes(clinic_name.strip(), issued, serial, machine),
    }


def verify_key(key, public_key_bytes, expected_machine=None):
    """Return the parsed fields when `key` is genuine, else None.

    `expected_machine` is a machine code to bind against. When given, a key
    issued for a different machine is rejected, while a site-wide key (empty
    machine field) is still accepted. When None, binding is not checked.
    """
    if isinstance(public_key_bytes, str):
        try:
            public_key_bytes = bytes.fromhex(public_key_bytes)
        except ValueError:
            return None
    if not public_key_bytes:
        return None
    parsed = parse_key(key)
    if not parsed:
        return None
    if not ed25519_verify(public_key_bytes, parsed["signature"], parsed["message"]):
        return None
    if expected_machine is not None:
        bound = parsed["machine"]
        if bound and bound != normalise_machine_code(expected_machine):
            return None
    return parsed
