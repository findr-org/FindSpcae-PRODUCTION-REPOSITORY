"""Persistence operations for password and OAuth authentication identities.

Each identity belongs to one account and represents one login provider.
The service handles credential validation, authenticated provider linking,
authorization, and transaction boundaries. This repository is stateless,
uses the supplied AsyncSession, and never selects a database connection.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.models import AuthIdentity, AuthIdentityProviders


class AuthIdentityRepository:
    """Data access for account authentication methods and provider identities."""

    @staticmethod
    async def create(db: AsyncSession, identity: AuthIdentity) -> AuthIdentity:
        """Add a password or OAuth identity and flush without committing."""
        db.add(identity)
        await db.flush()
        return identity

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        identity_id: UUID,
        lock: bool = False,
    ) -> AuthIdentity | None:
        """Find an identity by ID; optionally lock it for an update."""
        query = select(AuthIdentity).where(AuthIdentity.id == identity_id)
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_account_and_provider(
        db: AsyncSession,
        account_id: UUID,
        provider: AuthIdentityProviders,
        lock: bool = False,
    ) -> AuthIdentity | None:
        """Find an account's identity for a provider, or None.

        A unique constraint permits at most one identity per account/provider.
        Use a primary session when locking or making authentication decisions.
        """
        query = select(AuthIdentity).where(
            AuthIdentity.account_id == account_id,
            AuthIdentity.provider == provider,
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_provider_subject(
        db: AsyncSession,
        provider: AuthIdentityProviders,
        provider_subject: str,
        lock: bool = False,
    ) -> AuthIdentity | None:
        """Find a Google/Apple identity by its stable provider subject.

        The service must validate the provider token and subject before
        calling this method. Email matching must not auto-link accounts.
        """
        query = select(AuthIdentity).where(
            AuthIdentity.provider == provider,
            AuthIdentity.provider_subject == provider_subject,
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_by_account_id(
        db: AsyncSession,
        account_id: UUID,
    ) -> list[AuthIdentity]:
        """List an account's authentication identities, oldest first."""
        result = await db.execute(
            select(AuthIdentity)
            .where(AuthIdentity.account_id == account_id)
            .order_by(AuthIdentity.created_at.asc(), AuthIdentity.id.asc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def save(
        db: AsyncSession,
        identity: AuthIdentity,
    ) -> AuthIdentity:
        """Flush changes to an existing identity without committing.

        Intended for an ORM instance associated with the supplied session;
        password hashing and provider-linking checks belong to services.
        """
        db.add(identity)
        await db.flush()
        return identity

    @staticmethod
    async def delete(db: AsyncSession, identity: AuthIdentity) -> None:
        """Delete an identity without committing; authorization is external."""
        await db.delete(identity)
        await db.flush()
