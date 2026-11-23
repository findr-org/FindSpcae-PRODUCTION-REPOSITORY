"""Persistence operations for rotating authentication refresh tokens.

A refresh token stores only the hash of a single-use credential and its
consumption timestamp. The authentication service handles token hashing,
expiry checks, replay detection, and atomic rotation within one primary
database transaction. This repository is stateless and never commits.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.models import AuthRefreshToken


class AuthRefreshTokenRepository:
    """Data access for refresh-token records and token rotation history."""

    @staticmethod
    async def create(
        db: AsyncSession,
        token: AuthRefreshToken,
    ) -> AuthRefreshToken:
        """Add a hashed refresh token and flush without committing.

        The database permits only one unconsumed token per session.
        """
        db.add(token)
        await db.flush()
        return token

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        token_id: UUID,
        lock: bool = False,
    ) -> AuthRefreshToken | None:
        """Find a refresh-token record by ID, optionally locking the row."""
        query = select(AuthRefreshToken).where(
            AuthRefreshToken.id == token_id
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_hash(
        db: AsyncSession,
        token_hash: str,
        lock: bool = False,
    ) -> AuthRefreshToken | None:
        """Find a token by its stored digest, including consumed tokens.

        Retaining consumed-token lookup supports service-level reuse
        detection. Never pass or persist a plaintext refresh token here.
        """
        query = select(AuthRefreshToken).where(
            AuthRefreshToken.token_hash == token_hash
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_unconsumed_by_session_id(
        db: AsyncSession,
        session_id: UUID,
        lock: bool = False,
    ) -> AuthRefreshToken | None:
        """Find a session's current unconsumed token, if one exists.

        Unconsumed does not imply unexpired or usable: the service must
        validate token expiry and session/account eligibility.
        """
        query = select(AuthRefreshToken).where(
            AuthRefreshToken.session_id == session_id,
            AuthRefreshToken.consumed_at.is_(None),
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_by_session_id(
        db: AsyncSession,
        session_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuthRefreshToken]:
        """List a session's token history, newest first.

        Intended for internal investigation or cleanup; never serialize
        stored token hashes in public API responses.
        """
        result = await db.execute(
            select(AuthRefreshToken)
            .where(AuthRefreshToken.session_id == session_id)
            .order_by(AuthRefreshToken.created_at.desc(), AuthRefreshToken.id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    async def save(
        db: AsyncSession,
        token: AuthRefreshToken,
    ) -> AuthRefreshToken:
        """Flush updates to a token, such as consumed_at, without committing.

        The service coordinates consumption and insertion of the next token
        atomically. Use a primary database session for token rotation.
        """
        db.add(token)
        await db.flush()
        return token

    @staticmethod
    async def delete(db: AsyncSession, token: AuthRefreshToken) -> None:
        """Hard-delete token history for controlled cleanup, without committing.

        Normal token rotation must consume records instead of deleting them.
        """
        await db.delete(token)
        await db.flush()
