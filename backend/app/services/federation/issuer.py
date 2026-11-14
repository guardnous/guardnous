"""GuardNous as an OpenID Connect issuer.

GuardNous holds one RSA key pair. It publishes the public half at
``<issuer>/.well-known/jwks.json`` and signs short-lived tokens with the
private half. A cloud provider that has been told to trust the issuer URL
exchanges such a token for temporary credentials, so no access key or client
secret is ever created or stored.

The private key never leaves the database, where it is encrypted with
``ENCRYPTION_KEY``. Functions here are synchronous (they are used from Celery
workers and, through a thread, from the API).
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid
from contextlib import contextmanager
from urllib.parse import urlparse

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.oidc import OidcSigningKey

TOKEN_TTL_SECONDS = 300
_engine = None


class FederationUnavailable(Exception):
    """Secretless connection cannot work on this installation; the message says why."""


def issuer_url() -> str:
    """The public HTTPS issuer URL, or raise with the reason there is none."""
    url = (settings.OIDC_ISSUER_URL or "").strip().rstrip("/")
    if not url and settings.BACKEND_URL.lower().startswith("https://"):
        url = settings.BACKEND_URL.rstrip("/")
    if not url:
        raise FederationUnavailable(
            "Connecting without access keys needs GuardNous to be reachable at a public HTTPS address, because the "
            "cloud provider downloads GuardNous's public key from it. Set OIDC_ISSUER_URL to that address."
        )
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname in ("localhost", "127.0.0.1"):
        raise FederationUnavailable(f"OIDC_ISSUER_URL must be a public https:// address, not '{url}'.")
    return url


def issuer_host_path() -> str:
    """Issuer without the scheme, as AWS writes it in provider ARNs and condition keys."""
    return issuer_url().removeprefix("https://")


@contextmanager
def _session():
    global _engine
    if _engine is None:
        _engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    with Session(_engine) as session:
        yield session


def _b64(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _create_key(session: Session) -> OidcSigningKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.core.encryption import encrypt_token

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode()
    numbers = private.public_key().public_numbers()
    n, e = _b64(numbers.n), _b64(numbers.e)
    kid = hashlib.sha256(f"{n}.{e}".encode()).hexdigest()[:32]
    key = OidcSigningKey(
        kid=kid, private_pem_encrypted=encrypt_token(pem),
        public_jwk={"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e},
    )
    session.add(key)
    session.commit()
    return key


def _signing_key(session: Session) -> OidcSigningKey:
    """The oldest key signs, so two processes that both created one agree on which to use."""
    key = session.execute(select(OidcSigningKey).order_by(OidcSigningKey.id)).scalars().first()
    if key is None:
        _create_key(session)
        key = session.execute(select(OidcSigningKey).order_by(OidcSigningKey.id)).scalars().first()
    return key


def jwks() -> dict:
    with _session() as session:
        _signing_key(session)
        keys = session.execute(select(OidcSigningKey).order_by(OidcSigningKey.id)).scalars().all()
        return {"keys": [k.public_jwk for k in keys]}


def discovery() -> dict:
    issuer = issuer_url()
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "jti"],
    }


def mint_token(subject: str, audience: str) -> str:
    """A token valid for five minutes that says "this is GuardNous acting as <subject>"."""
    from jose import jwt

    from app.core.encryption import decrypt_token

    issuer = issuer_url()
    with _session() as session:
        key = _signing_key(session)
        kid, pem = key.kid, decrypt_token(key.private_pem_encrypted)
    now = int(time.time())
    return jwt.encode(
        {"iss": issuer, "sub": subject, "aud": audience, "iat": now, "nbf": now - 30,
         "exp": now + TOKEN_TTL_SECONDS, "jti": uuid.uuid4().hex},
        pem, algorithm="RS256", headers={"kid": kid},
    )
