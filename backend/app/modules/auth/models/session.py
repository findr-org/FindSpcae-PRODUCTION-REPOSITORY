# ==========================#
# Session.py
# ==========================#


"""
Database model for authentication sessions.

This module manages persistent login sessions associated with
findspace authentication accounts.

A session represents an independently manageable login instance,
such as a user signed in through a mobile application or browser.

Responsibilities:
- Associate login sessions with authentication accounts.
- Maintain independent sessions for multiple devices or clients.
- Track the most recent successful session refresh activity.
- Track sliding inactivity expiration.
- Record session revocation.
- Store optional client metadata for session identification.
- Provide the parent record for refresh-token rotation history.

Not responsible for:
- Verifying passwords or external authentication providers.
- Generating access or refresh tokens.
- Hashing or storing refresh-token credentials.
- Rotating refresh tokens or detecting token reuse.
- Determining authorization permissions.
- Enforcing authentication rate limits.

Invariants:
- Every session belongs to exactly one AuthAccount.
- An account may have multiple concurrent sessions.
- A session must have a valid expiration timestamp.
- Session expiration is based on successful refresh activity.
- An expired session cannot be renewed.
- A revoked session cannot be reactivated.
- Refresh activity and refresh-token rotation must be atomic.
- Only eligible, active accounts may use existing sessions.
- Session expiration policies depend on the account domain.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from uuid import UUID
from datetime import datetime

from sqlalchemy.orm import mapped_column, Mapped, relationship
from sqlalchemy import String, DateTime, ForeignKey, CheckConstraint, Index

from app.infrastructure.database.base import BaseModel

if TYPE_CHECKING:
    from .account import AuthAccount
    from .refresh_token import AuthRefreshToken


class AuthSession(BaseModel):
    """
    Represents an independently managed authentication session.

    Each session belongs to one authentication account and tracks
    its current inactivity-expiration deadline, most recent
    successful refresh activity, and revocation state.

    Sessions may contain multiple historical refresh tokens,
    but only valid, unrevoked credentials can renew them.

    Optional device metadata supports session identification
    without acting as an authentication factor.
    """

    __tablename__ = "auth_session"

    account_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth_account.id", ondelete="RESTRICT"), nullable=False
    )

    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    device_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "expires_at > last_activity_at", "ck_auth_session_expiry_after_activity"
        ),
        Index("ix_auth_session_account_revoked", "account_id", "revoked_at"),
        Index("ix_auth_session_expires_at", "expires_at"),
    )

    account: Mapped[AuthAccount] = relationship(
        "AuthAccount", back_populates="sessions"
    )

    refresh_tokens: Mapped[list[AuthRefreshToken]] = relationship(
        "AuthRefreshToken", back_populates="session"
    )
