# ==========================#
# Account.py
# ==========================#

"""
Repository for authentication account persistence.

Provides asynchronous database operations for creating, retrieving,
updating, and deleting AuthAccount records.

Responsibilities:
- Create new authentication accounts.
- Retrieve accounts by their unique identifiers.
- Retrieve active authentication accounts.
- Persist modifications to existing accounts.
- Delete accounts when database constraints permit.

Design:
- Uses stateless asynchronous static methods.
- Receives an AsyncSession explicitly for every operation.
- Remains independent of primary/replica database selection.
- Flushes changes without committing transactions.
- Supports optional row-level locking for account retrieval.

Not responsible for:
- Managing database connections or sessions.
- Enforcing account lifecycle or authorization rules.
- Managing email addresses, credentials, or sessions.
- Committing or rolling back database transactions.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.enums import AccountStatus
from app.modules.auth.models import AuthAccount


class AuthAccountRepository:
    """
    Stateless data access interface for authentication accounts.

    Encapsulates SQLAlchemy persistence operations using asynchronous
    static methods without requiring class instantiation.

    Every method operates on the supplied AsyncSession, allowing
    multiple repositories to participate in the same transaction.

    Business rules, database routing, and transaction boundaries
    are managed outside this repository.
    """

    @staticmethod
    async def create(
        db: AsyncSession,
        account: AuthAccount,
    ) -> AuthAccount:
        """
        Add a new authentication account to the database session.

        Flushes the pending INSERT so database-generated values become
        available without committing the surrounding transaction.

        Args:
            db: Active asynchronous database session.
            account: New authentication account to persist.

        Returns:
            The persisted AuthAccount ORM instance.
        """
        db.add(account)
        await db.flush()
        return account

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        account_id: UUID,
        lock: bool = False,
    ) -> AuthAccount | None:
        """
        Retrieve an authentication account by its unique identifier.

        Optionally acquires a row-level lock for operations requiring
        transactional consistency.

        Args:
            db: Active asynchronous database session.
            account_id: Unique identifier of the account.
            lock: Whether to acquire a SELECT FOR UPDATE lock.

        Returns:
            The matching AuthAccount instance, or None if not found.
        """
        query = select(AuthAccount).where(AuthAccount.id == account_id)

        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_active_by_id(
        db: AsyncSession,
        account_id: UUID,
        lock: bool = False,
    ) -> AuthAccount | None:
        """
        Retrieve an account only if its status is ACTIVE.

        Excludes pending, suspended, and disabled accounts.
        Optionally acquires a row-level lock when requested.

        Args:
            db: Active asynchronous database session.
            account_id: Unique identifier of the account.
            lock: Whether to acquire a SELECT FOR UPDATE lock.

        Returns:
            The active AuthAccount instance, or None if no matching
            active account exists.
        """
        query = select(AuthAccount).where(
            AuthAccount.id == account_id,
            AuthAccount.status == AccountStatus.ACTIVE,
        )

        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def save(
        db: AsyncSession,
        account: AuthAccount,
    ) -> AuthAccount:
        """
        Persist changes to an authentication account.

        Adds or attaches the supplied ORM object to the session and
        flushes pending changes without committing the transaction.

        Intended for updating an existing account. This method does
        not perform an explicit upsert or replace every database field.

        Args:
            db: Active asynchronous database session.
            account: Authentication account containing the changes.

        Returns:
            The AuthAccount ORM instance.
        """
        db.add(account)
        await db.flush()
        return account

    @staticmethod
    async def delete(
        db: AsyncSession,
        account: AuthAccount,
    ) -> None:
        """
        Delete an authentication account from the database.

        Marks the supplied ORM instance for deletion and flushes
        the pending DELETE without committing the transaction.

        Deletion may fail if related records exist because of
        foreign-key restrictions or other database constraints.

        Args:
            db: Active asynchronous database session.
            account: Authentication account to delete.

        Returns:
            None.
        """
        await db.delete(account)
        await db.flush()
        return None
