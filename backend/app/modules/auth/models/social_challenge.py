# ==========================#
# Social_challenge.py
# ==========================#

"""
Database model for short-lived social authentication challenges.

This module persists nonce digests used to bind external identity
tokens to individual Google or Apple authentication attempts.

Responsibilities:
- Identify the social provider associated with each challenge.
- Store a SHA-256 digest of the expected provider nonce claim.
- Track challenge expiration, consumption, and invalidation.
- Bind identity-linking challenges to an existing account.
- Support expiration-based cleanup of challenge records.

Not responsible for:
- Generating or returning plaintext nonces.
- Performing provider-specific nonce transformations.
- Verifying external identity tokens or nonce claims.
- Creating accounts, linking identities, or issuing sessions.
- Enforcing request-level rate limits.

Invariants:
- Only Google and Apple may be used as challenge providers.
- Nonce digests must be unique and plaintext nonces are not persisted.
- A null account_id denotes a sign-in challenge; a non-null account_id
  denotes an identity-linking challenge for that specific account.
- Expired, consumed, or invalidated challenges must not be accepted.
- Successful verification and challenge consumption must be atomic.
- The service must compare the digest of the verified nonce claim
  against nonce_hash, using the provider's nonce representation.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database.base import BaseModel
from app.modules.auth.enums import AuthIdentityProviders


class AuthSocialChallenge(BaseModel):
    """Single-use nonce challenge for social sign-in or identity linking."""

    __tablename__ = "auth_social_challenge"

    provider: Mapped[AuthIdentityProviders] = mapped_column(
        SQLEnum(
            AuthIdentityProviders,
            name="auth_identity_providers",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )

    account_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth_account.id", ondelete="CASCADE"),
        nullable=True,
    )

    nonce_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    invalidated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint(
            "provider IN ('google', 'apple')",
            name="ck_auth_social_challenge_provider",
        ),
        CheckConstraint(
            "nonce_hash ~ '^[0-9a-f]{64}$'",
            name="ck_auth_social_challenge_nonce_hash",
        ),
        UniqueConstraint(
            "nonce_hash",
            name="uq_auth_social_challenge_nonce_hash",
        ),
        Index(
            "ix_auth_social_challenge_expires_at",
            "expires_at",
        ),
        Index(
            "ix_auth_social_challenge_account_id",
            "account_id",
        ),
    )
