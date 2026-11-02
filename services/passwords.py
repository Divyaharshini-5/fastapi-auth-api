import hashlib
import hmac
import secrets


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 390_000)
    return f"{salt.hex()}${password_hash.hex()}"


def verify_password(password: str, stored_value: str) -> bool:
    salt_hex, expected_hash = stored_value.split("$", maxsplit=1)
    calculated_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), 390_000
    ).hex()
    return hmac.compare_digest(calculated_hash, expected_hash)
