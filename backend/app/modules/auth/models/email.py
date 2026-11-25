# ==========================#
# Email.py
# ==========================#

"""
Database model for authentication email addresses.

This module manages the email addresses associated with a
findspace authentication account.

An account may own multiple email addresses originating from
manual registration or external authentication providers.

Responsibilities:
- Associate multiple email addresses with one authentication account.
- Enforce globally unique, case-insensitive email ownership.
- Track email verification status and timestamps.
- Identify an account's preferred primary contact email.
- Control which emails are eligible for password-based login.
- Record the original source of an email address.

Not responsible for:
- Storing account credentials or password hashes.
- Authenticating external identity providers.
- Generating or validating verification OTPs.
- Managing authentication sessions or access tokens.

Invariants:
- Every email belongs to exactly one authentication account.
- An email address cannot belong to multiple accounts.
- An account can have at most one primary email.
- Only verified emails may become primary.
- Password login requires a verified, eligible email and
  an existing password authentication identity.
- Email addresses must be normalized before persistence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID
from datetime import datetime

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
    func,
    text,
    Enum as SQLEnum,
    CheckConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.database.base import BaseModel
from app.modules.auth.enums import EmailSource


if TYPE_CHECKING:
    from .account import AuthAccount
    from .challenge import AuthVerificationChallenge


class AuthEmail(BaseModel):
    """
    Represents an email address owned by an authentication account.

    Each address has an independent verification state and may
    be designated as the primary contact email or enabled for
    password authentication.

    Multiple email records may reference the same AuthAccount,
    but each normalized email address must be globally unique.
    """

    __tablename__ = "auth_email"

    account_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "auth_account.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(254),
        nullable=False,
    )

    source: Mapped[EmailSource] = mapped_column(
        SQLEnum(
            EmailSource,
            name="email_source",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )

    is_primary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    password_login_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "uq_auth_email_lower",
            func.lower(email),
            unique=True,
        ),
        Index(
            "uq_auth_email_primary",
            "account_id",
            unique=True,
            postgresql_where=text("is_primary = TRUE"),
        ),
        CheckConstraint(
            "NOT is_primary OR verified_at IS NOT NULL",
            name="ck_auth_email_primary_verified",
        ),
    )

    account: Mapped[AuthAccount] = relationship(
        "AuthAccount",
        back_populates="emails",
    )

    challenges: Mapped[list[AuthVerificationChallenge]] = relationship(
        "AuthVerificationChallenge", back_populates="email"
    )
