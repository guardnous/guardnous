"""Tests for encryption utilities."""
import pytest
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.core.encryption import encrypt_token, decrypt_token


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        original = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        encrypted = encrypt_token(original)
        assert encrypted != original
        decrypted = decrypt_token(encrypted)
        assert decrypted == original

    def test_encrypted_is_different_each_time(self):
        token = "sk_live_test_token_12345"
        enc1 = encrypt_token(token)
        enc2 = encrypt_token(token)
        # Fernet uses random IV, so each encryption is different
        assert enc1 != enc2
        # But both decrypt to the same value
        assert decrypt_token(enc1) == token
        assert decrypt_token(enc2) == token

    def test_decrypt_invalid_token(self):
        with pytest.raises(ValueError, match="Failed to decrypt"):
            decrypt_token("not-a-valid-encrypted-token")

    def test_empty_string(self):
        encrypted = encrypt_token("")
        assert decrypt_token(encrypted) == ""

    def test_long_token(self):
        long_token = "x" * 1000
        encrypted = encrypt_token(long_token)
        assert decrypt_token(encrypted) == long_token

    def test_unicode_token(self):
        token = "token-with-ünïcödé-chars"
        encrypted = encrypt_token(token)
        assert decrypt_token(encrypted) == token
