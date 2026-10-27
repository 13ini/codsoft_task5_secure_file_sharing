
from cryptography.fernet import Fernet, InvalidToken

from config import FILE_ENCRYPTION_KEY


_cipher = Fernet(FILE_ENCRYPTION_KEY.encode("ascii"))


def encrypt_file(data: bytes) -> bytes:
    """Encrypt file bytes before storage."""
    if not isinstance(data, bytes):
        raise TypeError("File data must be bytes.")
    return _cipher.encrypt(data)


def decrypt_file(encrypted_data: bytes) -> bytes:
    """Decrypt stored file bytes."""
    if not isinstance(encrypted_data, bytes):
        raise TypeError("Encrypted data must be bytes.")

    try:
        return _cipher.decrypt(encrypted_data)
    except InvalidToken as exc:
        raise ValueError(
            "File decryption failed: invalid key or altered encrypted data."
        ) from exc
