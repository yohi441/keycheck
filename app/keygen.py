import secrets

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_key() -> str:
    chars = "".join(secrets.choice(ALPHABET) for _ in range(16))
    return "-".join(chars[i:i + 4] for i in range(0, 16 ,4))