
from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password: str) -> str:
    """Return a secure hash of a password."""
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    return generate_password_hash(password, method="scrypt")


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against its stored hash."""
    if not isinstance(password_hash, str) or not isinstance(password, str):
        return False

    try:
        return check_password_hash(password_hash, password)
    except (ValueError, TypeError):
        return False
