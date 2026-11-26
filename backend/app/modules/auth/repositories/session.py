"""Persistence operations for authentication sessions.

A session represents a login on one device or client. This repository
handles persistence, lookups, and listing only; services decide session
eligibility, inactivity expiry, and revocation policy. It receives an
AsyncSession explicitly, does not select a database, and never commits.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select , update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.models import AuthSession


class AuthSessionRepository:
    """Stateless data access for account login sessions."""

    @staticmethod
    async def create(db: AsyncSession, session: AuthSession) -> AuthSession:
        """Add a login session and flush its INSERT without committing."""
        db.add(session)
        await db.flush()
        return session

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        session_id: UUID,
        lock: bool = False,
    ) -> AuthSession | None:
        """Find a session by ID, optionally locking it for modification."""
        query = select(AuthSession).where(AuthSession.id == session_id)
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_active_by_id(
        db: AsyncSession,
        session_id: UUID,
        now: datetime,
        lock: bool = False,
    ) -> AuthSession | None:
        """Find a non-revoked, unexpired session or return None.

        `now` must be timezone-aware. An active session still requires
        a permitted account status and valid credentials to authenticate.
        """
        query = select(AuthSession).where(
            AuthSession.id == session_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_by_account_id(
        db: AsyncSession,
        account_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuthSession]:
        """List sessions for an account, newest first, including revoked ones.

        The caller validates pagination and determines which sessions
        should be presented as active.
        """
        result = await db.execute(
            select(AuthSession)
            .where(AuthSession.account_id == account_id)
            .order_by(AuthSession.created_at.desc(), AuthSession.id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    async def save(db: AsyncSession, session: AuthSession) -> AuthSession:
        """Flush session changes without committing.

        The service is responsible for revocation policy, refresh activity,
        expiry calculations, and concurrent token rotation.
        """
        db.add(session)
        await db.flush()
        return session

    @staticmethod
    async def delete(db: AsyncSession, session: AuthSession) -> None:
        """Hard-delete a session for controlled cleanup, without committing.

        This is not logout: logout should set revoked_at through the service.
        Refresh tokens reference the session with ON DELETE CASCADE.
        """
        await db.delete(session)
        await db.flush()



    @staticmethod
    async def update_revoked_at_by_account_id(
        db: AsyncSession,
        account_id: UUID,
        revoked_time: datetime,
        *,
        exclude_session_id: UUID | None = None,
    ) -> int:
        query = (
            update(AuthSession)
            .where(
                AuthSession.account_id == account_id,
                AuthSession.revoked_at.is_(None),
            )
            .values(revoked_at=revoked_time)
            .execution_options(synchronize_session="fetch")
        )

        if exclude_session_id is not None:
            query = query.where(
                AuthSession.id != exclude_session_id
            )

        result = await db.execute(query)

        return result.rowcount  # type: ignore[attr-defined]
