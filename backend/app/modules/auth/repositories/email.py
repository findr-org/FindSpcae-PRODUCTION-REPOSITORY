"""Persistence operations for email addresses owned by auth accounts.

An account may have multiple email records, but each address is globally
unique (case-insensitively) and only one verified email may be primary.

This stateless repository executes queries using the supplied AsyncSession.
It does not choose primary versus replica connections, decide email ownership,
verify OTPs, enforce authentication policy, or commit transactions.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.models import AuthEmail


class AuthEmailRepository:
    """Data access for AuthEmail; callers own validation and transactions."""

    @staticmethod
    async def create(db: AsyncSession, email: AuthEmail) -> AuthEmail:
        """Add an email record and flush its INSERT without committing."""
        db.add(email)
        await db.flush()
        return email

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        email_id: UUID,
        lock: bool = False,
    ) -> AuthEmail | None:
        """Find an email by record ID, optionally locking the row.

        Row locks require a primary database session and an open transaction.
        Return None when the record does not exist.
        """
        query = select(AuthEmail).where(AuthEmail.id == email_id)
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(
        db: AsyncSession,
        email: str,
        lock: bool = False,
    ) -> AuthEmail | None:
        """Find an email address regardless of case or surrounding whitespace.

        Uses the same lower(email) expression as the model's unique index.
        Return None when the address is not registered.
        """
        normalized_email = email.strip().lower()
        query = select(AuthEmail).where(
            func.lower(AuthEmail.email) == normalized_email
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_by_account_id(
        db: AsyncSession,
        account_id: UUID,
    ) -> list[AuthEmail]:
        """List all email records owned by an account, oldest first."""
        result = await db.execute(
            select(AuthEmail)
            .where(AuthEmail.account_id == account_id)
            .order_by(AuthEmail.created_at.asc(), AuthEmail.id.asc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_primary_by_account_id(
        db: AsyncSession,
        account_id: UUID,
        lock: bool = False,
    ) -> AuthEmail | None:
        """Find an account's primary email, or None if none is assigned.

        The database enforces at most one primary email per account.
        """
        query = select(AuthEmail).where(
            AuthEmail.account_id == account_id,
            AuthEmail.is_primary.is_(True),
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_password_login_email(
        db: AsyncSession,
        email: str,
        lock: bool = False,
    ) -> AuthEmail | None:
        """Find a verified address enabled for password-based login.

        This checks email eligibility only; the service must also verify the
        password identity and account status on the primary database.
        """
        normalized_email = email.strip().lower()
        query = select(AuthEmail).where(
            func.lower(AuthEmail.email) == normalized_email,
            AuthEmail.password_login_enabled.is_(True),
            AuthEmail.verified_at.is_not(None),
        )
        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def save(db: AsyncSession, email: AuthEmail) -> AuthEmail:
        """Flush pending changes to an email ORM instance without committing.

        Intended for records already associated with the supplied session;
        this is not an upsert or replacement operation.
        """
        db.add(email)
        await db.flush()
        return email

    @staticmethod
    async def delete(db: AsyncSession, email: AuthEmail) -> None:
        """Delete an email record and flush without committing.

        The service decides whether deletion is allowed. Associated
        verification challenges have a database-level CASCADE foreign key.
        """
        await db.delete(email)
        await db.flush()
