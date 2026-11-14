"""Encryption utilities for storing VCS tokens and secrets securely."""
from cryptography.fernet import Fernet, InvalidToken
from app.core.config import settings


def _get_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if "change-me" in key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not configured. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_token(plaintext: str) -> str:
    """Encrypt a VCS token for database storage."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a VCS token from database storage."""
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise ValueError("Failed to decrypt token - encryption key may have changed")
