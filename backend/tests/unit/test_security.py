from app.core.security import get_password_hash, verify_password, create_access_token
from jose import jwt
from app.core.config import settings


class TestSecurity:
    def test_password_hashing(self):
        password = "test-password-123"
        hashed = get_password_hash(password)
        assert hashed != password
        assert verify_password(password, hashed)

    def test_password_verification_fails(self):
        password = "test-password-123"
        hashed = get_password_hash(password)
        assert not verify_password("wrong-password", hashed)

    def test_create_access_token(self):
        token = create_access_token(data={"sub": "1"})
        assert token
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == "1"

    def test_token_contains_expiry(self):
        token = create_access_token(data={"sub": "1"})
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert "exp" in payload
