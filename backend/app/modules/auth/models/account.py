# ==========================#
# Account.py
# ==========================#

"""
Database model for the central authentication account.

This module defines the parent authentication account shared by
marketplace users, staff members, and administrators.

Responsibilities:
- Maintain the central authentication account identity.
- Classify accounts by domain: user, staff, or administrator.
- Track account lifecycle: pending, active, suspended, or disabled.
- Establish relationships with email addresses, authentication
  identities, and sessions.

Not responsible for:
- Storing or verifying email addresses (see AuthEmail).
- Storing credentials or password hashes (see AuthIdentity).
- Issuing or validating authentication tokens.
- Managing marketplace, staff, or administrator profiles.

Invariants:
- Every account belongs to exactly one account domain.
- Only ACTIVE accounts are eligible for authentication.
- Account types and lifecycle states are controlled by trusted
  backend operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from enum import Enum as PyEnum

from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.database.base import BaseModel


if TYPE_CHECKING:
    from .email import AuthEmail
    from .identity import AuthIdentity
    from .session import AuthSession


class AccountType(str, PyEnum):
    USER = "user"
    STAFF = "staff"
    ADMIN = "admin"


class AccountStatus(str, PyEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class AuthAccount(BaseModel):
    """Central authentication account for all findspace account domains."""

    __tablename__ = "auth_account"

    account_type: Mapped[AccountType] = mapped_column(
        SQLEnum(
            AccountType,
            name="account_type",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )

    status: Mapped[AccountStatus] = mapped_column(
        SQLEnum(
            AccountStatus,
            name="account_status",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
        default=AccountStatus.PENDING,
        server_default=AccountStatus.PENDING.value,
    )

    emails: Mapped[list[AuthEmail]] = relationship(
        "AuthEmail",
        back_populates="account",
    )

    identities: Mapped[list[AuthIdentity]] = relationship(
        "AuthIdentity", back_populates="account"
    )

    sessions: Mapped[list[AuthSession]] = relationship(
        "AuthSession", back_populates="account"
    )
