"""Persistence operations for email verification and password-reset challenges.

Challenges store hashed OTPs, expiry, attempt count, and consumption status.
The service handles generating and checking codes, attempt limits, challenge
invalidation policy, and atomic state changes. This stateless repository
uses only the supplied AsyncSession and never commits or chooses an engine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable
from uuid import UUID

from sqlalchemy import select , update
from sqlalchemy.engine.result import scalar_one_or_none
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.enums import VerificationPurpose
from app.modules.auth.models import AuthVerificationChallenge


class AuthVerificationChallengeRepository:
    """Data access for single-purpose, expiring email verification challenges."""

    @staticmethod
    async def create(
        db: AsyncSession,
        challenge: AuthVerificationChallenge,
    ) -> AuthVerificationChallenge:
        """Add a hashed verification challenge and flush without committing."""
        db.add(challenge)
        await db.flush()
        return challenge

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        challenge_id: UUID,
        lock: bool = False,
    ) -> AuthVerificationChallenge | None:
        """Find a challenge by ID, optionally locking the record."""
        query = select(AuthVerificationChallenge).where(
            AuthVerificationChallenge.id == challenge_id
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_latest_pending(
        db: AsyncSession,
        email_id: UUID,
        purpose: VerificationPurpose,
        now: datetime,
        lock: bool = False,
    ) -> AuthVerificationChallenge | None:
        """Get the newest unconsumed, uninvalidated, unexpired challenge.

        The supplied `now` must be timezone-aware. The service must still
        verify the code and enforce attempt limits under the same transaction.
        """
        query = (
            select(AuthVerificationChallenge)
            .where(
                AuthVerificationChallenge.email_id == email_id,
                AuthVerificationChallenge.purpose == purpose,
                AuthVerificationChallenge.consumed_at.is_(None),
                AuthVerificationChallenge.invalidated_at.is_(None),
                AuthVerificationChallenge.expires_at > now,
            )
            .order_by(
                AuthVerificationChallenge.created_at.desc(),
                AuthVerificationChallenge.id.desc(),
            )
            .limit(1)
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_pending_by_email_and_purpose(
        db: AsyncSession,
        email_id: UUID,
        purpose: VerificationPurpose,
        lock: bool = False,
    ) -> list[AuthVerificationChallenge]:
        """List unconsumed, uninvalidated challenges for an email and purpose.

        Includes expired rows so a service can invalidate outstanding
        challenges when issuing a replacement. No automatic cleanup occurs.
        """
        query = (
            select(AuthVerificationChallenge)
            .where(
                AuthVerificationChallenge.email_id == email_id,
                AuthVerificationChallenge.purpose == purpose,
                AuthVerificationChallenge.consumed_at.is_(None),
                AuthVerificationChallenge.invalidated_at.is_(None),
            )
            .order_by(AuthVerificationChallenge.created_at.desc())
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def save(
        db: AsyncSession,
        challenge: AuthVerificationChallenge,
    ) -> AuthVerificationChallenge:
        """Flush updates to an existing challenge without committing.

        Consumption and verification-related updates must be coordinated
        atomically by the calling authentication service.
        """
        db.add(challenge)
        await db.flush()
        return challenge

    @staticmethod
    async def delete(
        db: AsyncSession,
        challenge: AuthVerificationChallenge,
    ) -> None:
        """Delete a challenge for controlled cleanup, without committing."""
        await db.delete(challenge)
        await db.flush()


    @staticmethod
    async def get_latest_by_email_and_purpose(
        db : AsyncSession,
        email_id : UUID,
        purpose : VerificationPurpose
    ) -> AuthVerificationChallenge | None:
        query = select(AuthVerificationChallenge).where(
            AuthVerificationChallenge.email_id == email_id,
            AuthVerificationChallenge.purpose == purpose
        ).order_by(
            AuthVerificationChallenge.created_at.desc(),
            AuthVerificationChallenge.id.desc()
        ).limit(1)


        result = await db.execute(query)
        return result.scalar_one_or_none()



    @staticmethod
    async def update_invalidated_at_by_ids(
        db: AsyncSession,
        challenge_ids: list[UUID],
        invalidated_at: datetime,
    ) -> int:
        if not challenge_ids:
            return 0

        query = (
            update(AuthVerificationChallenge)
            .where(
                AuthVerificationChallenge.id.in_(challenge_ids),
                AuthVerificationChallenge.consumed_at.is_(None),
                AuthVerificationChallenge.invalidated_at.is_(None),
            )
            .values(invalidated_at=invalidated_at)
            .returning(AuthVerificationChallenge.id)
        )

        result = await db.execute(query)

        return len(result.scalars().all())