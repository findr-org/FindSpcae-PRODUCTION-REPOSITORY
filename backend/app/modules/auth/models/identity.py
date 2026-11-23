# ==========================#
# Identity.py
# ==========================#

"""
Database model for authentication identities.

This module defines the authentication methods associated with
a findspace account.

An authentication account may have multiple identities, allowing
users to authenticate through email/password, Google, or Apple
without creating separate accounts.

Responsibilities:
- Associate authentication methods with an AuthAccount.
- Identify the authentication provider for each identity.
- Store password hashes for password-based authentication.
- Store stable provider subject identifiers for OAuth identities.
- Prevent duplicate authentication methods on the same account.
- Prevent external provider identities from belonging to
  multiple accounts.

Not responsible for:
- Storing email addresses or their verification status.
- Determining the account's primary email.
- Generating or verifying OTP challenges.
- Issuing access or refresh tokens.
- Managing device sessions.
- Performing OAuth token exchange or validation.

Invariants:
- Every authentication identity belongs to one account.
- An account may have at most one identity per provider.
- A provider subject is unique within its provider.
- PASSWORD identities require a password hash.
- PASSWORD identities must not have a provider subject.
- GOOGLE and APPLE identities require a provider subject.
- GOOGLE and APPLE identities must not store password hashes.
- Authentication providers cannot be linked automatically
  merely because their email addresses match.
- Linking a new provider requires an authenticated session
  and appropriate security checks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from enum import Enum as PyEnum
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Enum as SQLEnum,
    ForeignKey,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.database.base import BaseModel


if TYPE_CHECKING:
    from .account import AuthAccount


class AuthIdentityProviders(str, PyEnum):
    """States the multiple channels a user can use to authenticate."""

    PASSWORD = "password"
    GOOGLE = "google"
    APPLE = "apple"


class AuthIdentity(BaseModel):
    __tablename__ = "auth_identity"

    account_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "auth_account.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    provider: Mapped[AuthIdentityProviders] = mapped_column(
        SQLEnum(
            AuthIdentityProviders,
            name="auth_identity_providers",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )

    provider_subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    password_hash: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "account_id",
            "provider",
            name="uq_auth_identity_account_provider",
        ),
        UniqueConstraint(
            "provider",
            "provider_subject",
            name="uq_auth_identity_provider_subject",
        ),
        CheckConstraint(
            "("
            "provider = 'password' "
            "AND provider_subject IS NULL "
            "AND password_hash IS NOT NULL"
            ") OR ("
            "provider IN ('google', 'apple') "
            "AND provider_subject IS NOT NULL "
            "AND password_hash IS NULL"
            ")",
            name="ck_auth_identity_credentials",
        ),
    )

    account: Mapped[AuthAccount] = relationship(
        "AuthAccount",
        back_populates="identities",
    )
