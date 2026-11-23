# ==========================#
# Challenge.py
# ==========================#

"""
Database model for authentication verification challenges.

This module stores short-lived verification challenges used to
prove email ownership and authorize password recovery.

Each challenge belongs to a specific AuthEmail record and has
a defined purpose, expiration time, and consumption state.

Responsibilities:
- Associate verification challenges with an email address.
- Identify the purpose of each challenge.
- Store a secure digest of the verification code.
- Track challenge expiration.
- Record unsuccessful verification attempts.
- Record successful challenge consumption.
- Allow challenges to be invalidated before expiration.

Not responsible for:
- Generating plaintext OTP codes.
- Sending verification emails.
- Comparing or validating submitted OTP codes.
- Enforcing request-level rate limits.
- Updating email verification status.
- Changing account passwords.
- Issuing authentication tokens or sessions.

Invariants:
- Every challenge belongs to an existing AuthEmail.
- Every challenge has a single, explicit purpose.
- Plaintext OTP codes must never be persisted.
- A challenge expires at its configured expiration time.
- A consumed challenge cannot be used again.
- An invalidated challenge cannot be used.
- Verification attempts must be limited.
- Successful verification and challenge consumption must
  be handled atomically by the authentication service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from datetime import datetime
from enum import Enum as PyEnum
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Integer,
    String,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.database.base import BaseModel


if TYPE_CHECKING:
    from .email import AuthEmail


class VerificationPurpose(str, PyEnum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class AuthVerificationChallenge(BaseModel):
    """
    Represents a short-lived authentication verification challenge.

    A challenge is associated with a specific email address and
    purpose, and stores only a secure digest of the OTP.

    Its lifecycle is controlled through expiration, unsuccessful
    attempt counts, successful consumption, and invalidation.
    """

    __tablename__ = "auth_verification_challenge"

    email_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "auth_email.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    purpose: Mapped[VerificationPurpose] = mapped_column(
        SQLEnum(
            VerificationPurpose,
            name="verification_purpose",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )

    code_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
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
            "attempt_count >= 0",
            name="ck_auth_verification_challenge_attempt_count",
        ),
        Index(
            "ix_auth_verification_challenge_email_purpose",
            "email_id",
            "purpose",
        ),
    )

    email: Mapped[AuthEmail] = relationship(
        "AuthEmail",
        back_populates="challenges",
    )
