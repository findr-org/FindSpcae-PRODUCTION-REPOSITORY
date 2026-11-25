# ==========================#
# Social_challenge.py
# ==========================#

"""
Persistence operations for social authentication nonce challenges.

Responsibilities:
- Create challenges and retrieve them by their identifiers.
- Atomically consume an active challenge bound to the expected provider,
  account, and verified nonce digest.
- Invalidate outstanding challenges and delete records for controlled cleanup.

Not responsible for:
- Generating nonces or verifying external identity tokens.
- Deciding whether an account may sign in or link an identity.
- Choosing database engines or committing transactions.

Invariants:
- All operations use the caller's AsyncSession.
- Mutating operations must use the primary database.
- The service must verify the signed nonce claim before consumption.
- Consumption and subsequent authentication changes belong to the same
  transaction; the service must stop if consumption returns False.
- Expiration is evaluated using the PostgreSQL wall clock for consumption.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.enums import AuthIdentityProviders
from app.modules.auth.models import AuthSocialChallenge


class AuthSocialChallengeRepository:
    """Stateless persistence interface for single-use social challenges."""

    @staticmethod
    async def create(
        db: AsyncSession,
        challenge: AuthSocialChallenge,
    ) -> AuthSocialChallenge:
        """Persist a challenge and flush without committing."""
        db.add(challenge)
        await db.flush()
        return challenge

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        challenge_id: UUID,
        lock: bool = False,
    ) -> AuthSocialChallenge | None:
        """Retrieve a challenge, optionally acquiring a primary row lock."""
        query = select(AuthSocialChallenge).where(
            AuthSocialChallenge.id == challenge_id
        )
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def consume(
        db: AsyncSession,
        challenge_id: UUID,
        provider: AuthIdentityProviders,
        nonce_hash: str,
        account_id: UUID | None,
    ) -> bool:
        """Atomically consume an active challenge matching verified context.

        A null account_id matches sign-in challenges only. The caller must
        supply the authenticated account ID for identity linking and the
        digest of the nonce claim from a successfully verified token.

        Returns False if no eligible row was updated. A True result remains
        provisional until the caller commits the surrounding transaction.
        """
        query = (
            update(AuthSocialChallenge)
            .where(
                AuthSocialChallenge.id == challenge_id,
                AuthSocialChallenge.provider == provider,
                AuthSocialChallenge.nonce_hash == nonce_hash,
                AuthSocialChallenge.account_id == account_id,
                AuthSocialChallenge.consumed_at.is_(None),
                AuthSocialChallenge.invalidated_at.is_(None),
                AuthSocialChallenge.expires_at > func.clock_timestamp(),
            )
            .values(consumed_at=func.clock_timestamp())
            .returning(AuthSocialChallenge.id)
            .execution_options(synchronize_session="fetch")
        )
        result = await db.execute(query)
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def invalidate(
        db: AsyncSession,
        challenge_id: UUID,
    ) -> bool:
        """Invalidate an unconsumed challenge without committing.

        Expired challenges may also be invalidated. Authorization to
        invalidate the specified challenge is the caller's responsibility.
        """
        query = (
            update(AuthSocialChallenge)
            .where(
                AuthSocialChallenge.id == challenge_id,
                AuthSocialChallenge.consumed_at.is_(None),
                AuthSocialChallenge.invalidated_at.is_(None),
            )
            .values(invalidated_at=func.clock_timestamp())
            .returning(AuthSocialChallenge.id)
            .execution_options(synchronize_session="fetch")
        )
        result = await db.execute(query)
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def delete(
        db: AsyncSession,
        challenge: AuthSocialChallenge,
    ) -> None:
        """Delete a challenge for service-controlled cleanup without committing."""
        await db.delete(challenge)
        await db.flush()
