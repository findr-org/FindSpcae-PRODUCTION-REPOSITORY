# ==========================#
# Secutiry.py
# ==========================#


"""
This app is solely responsible for core security utilities,
like password hasing , generation , jwt access token creation and refresh tokens
"""

from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import hmac
from typing import Any
import uuid

from jose import jwt, JWTError
from pwdlib import PasswordHash
from app.infrastructure.config import settings

password_hasher = PasswordHash.recommended()


# ==========================#
# PASSWORD HASH
# ==========================#
def hash_password(password: str) -> str:
    """Return a salted Argon2id hash of the password for storage."""
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return True if the password matches the stored hash."""
    return password_hasher.verify(password, password_hash)


# ==========================#
# TOKENS JWT AND REFRESH
# ==========================#


def generate_token_jti() -> str:
    """Generate a unique token/session identifier"""

    return uuid.uuid4().hex


def generate_refresh_token() -> str:
    """
    Generate a high entropy raw refresh token

    This raw value is sent to the client as an HTTPOnly cookie
    It must never be stored directly in the database
    """

    return secrets.token_urlsafe(64)


def hash_refresh_token(refresh_token: str) -> str:
    """Hash a refresh token for database persistence"""

    digest = hmac.new(
        settings.SECRET_KEY.get_secret_value().encode("utf-8"),
        refresh_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"refresh_sha256${digest}"


def verify_refresh_token(refresh_token: str, hashed_refresh_token: str) -> bool:
    """Return whether a raw refresh token matches a stored refresh-token hash"""

    return hmac.compare_digest(hash_refresh_token(refresh_token), hashed_refresh_token)


def create_access_token(
    data: dict,
    expires_delta: timedelta,
    *,
    session_jti: str | None = None,
    token_jti: str | None = None,
) -> str:
    """Create and sign a JWT access token
    Extra claims:
    - token_type: identifies this as an access token
    - jti: unique ID for this specific access token
    - sid: session ID/token-family ID when session auth is enabled

    keeping data as the first argument preserves the existing call sites
    """

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + expires_delta

    to_encode.update(
        {
            "exp": expire,
            "token_type": "access",
            "jti": token_jti or generate_token_jti(),
        }
    )

    if session_jti is not None:
        to_encode["sid"] = session_jti

    return jwt.encode(
        claims=to_encode,
        algorithm=settings.ALGORITHM,
        key=settings.SECRET_KEY.get_secret_value(),
    )


def decode_access_token(access_token: str) -> dict[str, Any]:
    """Validate an access JWT's signature, expiration and required claims."""
    try:
        claims = jwt.decode(
            token=access_token,
            key=settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM],
            options={
                "require_exp": True,
                "require_sub": True,
                "require_jti": True,
            },
        )

        if (
            claims.get("token_type") != "access"
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"].strip()
            or not isinstance(claims.get("jti"), str)
            or not claims["jti"].strip()
        ):
            raise JWTError("Invalid access token claims")

        return claims
    except JWTError as exc:
        raise JWTError("Invalid or expired access token") from exc


# ======================================#
# OTP generation hashing and verification
# =======================================#


def generate_otp(length: int) -> str:
    return f"{secrets.randbelow(10**length):0{length}d}"


def hash_otp(otp_code: str):
    """Hash an OTP code with HMAC-SHA256 using the application secret"""

    digest = hmac.new(
        settings.SECRET_KEY.get_secret_value().encode("utf-8"),
        otp_code.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"otp_sha256${digest}"


def verify_otp(otp_code: str, hashed_otp: str) -> bool:
    """Verify an OTP using HMAC-SHA256."""

    if not hashed_otp.startswith("otp_sha256$"):
        return False

    return hmac.compare_digest(hash_otp(otp_code), hashed_otp)
