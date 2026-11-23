# ==========================#
# Refresh_token.py
# ==========================#


"""
Database model for authentication refresh tokens.

This module stores refresh-token credentials and rotation history
for persistent findspace authentication sessions.

Each refresh token belongs to a single AuthSession. Tokens are
single-use credentials: successful refresh operations consume the
current token and issue a replacement.

Responsibilities:
- Associate refresh tokens with authentication sessions.
- Store cryptographic digests instead of plaintext tokens.
- Track individual token expiration.
- Record when a token has been consumed through rotation.
- Preserve token history for replay and reuse detection.
- Prevent duplicate token digests.
- Enforce at most one unconsumed token per session.

Not responsible for:
- Generating random refresh tokens.
- Computing or comparing cryptographic digests.
- Creating or validating access tokens.
- Performing refresh-token rotation transactions.
- Revoking authentication sessions.
- Detecting or responding to token compromise.
- Managing account authentication methods.

Invariants:
- Every refresh token belongs to exactly one AuthSession.
- Plaintext refresh tokens must never be persisted.
- Token digests must be globally unique.
- A session may have many historical refresh tokens.
- A session may have at most one unconsumed refresh token.
- Consumed tokens cannot be used again.
- Expired tokens cannot renew a session.
- Revoked or expired sessions cannot be refreshed.
- Rotation must atomically consume the previous token,
  create its replacement, and extend the session lifetime.
- Reuse of a previously consumed token must trigger
  the configured session compromise response.
"""

from __future__ import annotations
from uuid import UUID
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy.orm import mapped_column, Mapped, relationship
from sqlalchemy import String, UUID, DateTime, ForeignKey, UniqueConstraint, Index

from app.infrastructure.database.base import BaseModel

if TYPE_CHECKING:
    from .session import AuthSession


class AuthRefreshToken(BaseModel):
    """
    Represents a single-use refresh-token credential.

    Each refresh token belongs to one authentication session and
    stores only a cryptographic digest of its original secret.

    Successful refresh operations consume the current token and
    create a replacement, preserving historical records for
    refresh-token replay detection.

    Token validity also depends on the associated session and
    account remaining active and eligible for authentication.
    """

    __tablename__ = "auth_refresh_token"

    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth_session.id", ondelete="RESTRICT"), nullable=False
    )

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "token_hash",
            name="uq_auth_refresh_token_hash",
        ),
        Index(
            "uq_auth_refresh_token_current",
            "consumed_at  IS NULL",
            "session_id",
            unique=True,
        ),
        Index("ix_auth_refresh_token_expires_at", "expires_at"),
    )

    session: Mapped[AuthSession] = relationship(
        "AuthSession", back_populates="refresh_tokens"
    )
