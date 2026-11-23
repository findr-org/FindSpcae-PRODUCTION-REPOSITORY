
#==========================#
#Email.py
#==========================#


"""
Repository for authentication email persistence.

Provides asynchronous database operations for creating, retrieving,
updating, and deleting AuthEmail records.

Responsibilities:
- Create email records associated with authentication accounts.
- Retrieve email records by ID or email address.
- Retrieve all emails belonging to an account.
- Retrieve primary and password-login-eligible email records.
- Persist modifications to existing email records.
- Delete email records when permitted.

Design:
- Uses stateless asynchronous static methods.
- Receives an AsyncSession explicitly for every operation.
- Remains independent of primary/replica database selection.
- Supports row-level locking where appropriate.
- Flushes changes without committing transactions.

Not responsible for:
- Verifying email ownership or validating OTPs.
- Deciding which email should become primary.
- Managing password hashes or authentication identities.
- Enforcing account-level authorization rules.
- Managing database sessions or transaction boundaries.
"""




from __future__ import annotations
from uuid import UUID

from sqlalchemy import delete, select , delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.auth.models import AuthEmail 

class AuthEmailRepository:
    """
    Stateless data access interface for authentication emails.

    Encapsulates SQLAlchemy persistence and lookup operations
    for AuthEmail records using asynchronous static methods.

    Every method operates on the supplied AsyncSession.

    Email verification, ownership decisions, and primary-email
    selection rules are handled by the service layer.
    """



    @staticmethod
    async def create(
        db : AsyncSession,
        email : AuthEmail
    ) -> AuthEmail:
        db.add(email)
        await db.flush()
        return email



    @staticmethod
    async def get_by_id(
        db : AsyncSession,
        id : UUID,
        lock : bool = False
    ) -> AuthEmail | None:
        query = select(AuthEmail).where(
            AuthEmail.id == id
        )

        if lock:
            query = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()
        


    @staticmethod
    async def get_by_email(
        db : AsyncSession,
        email : AuthEmail,
        lock : bool = False
    ) -> AuthEmail | None:
        query = select(AuthEmail).where(
            AuthEmail.email == email
        )


        if lock:
            query  = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()



    
    @staticmethod
    async def get_primary_account_by_id(
        db : AsyncSession,
        id : AuthEmail,
        lock : bool = False
    ) -> AuthEmail | None:
        query = select(AuthEmail).where(
            AuthEmail.id == id,
            AuthEmail.is_primary == True
        )


        if lock:
            query  = query.with_for_update()

        result = await db.execute(query)
        return result.scalar_one_or_none()




    
    @staticmethod
    async def get_password_login_email(
        db : AsyncSession,
        id : AuthEmail,
        lock : bool = False
    ) -> AuthEmail | None:
        query = select(AuthEmail).where(
            AuthEmail.id == id,
            AuthEmail.password_login_enabled == True
        )
    
    
        if lock:
            query  = query.with_for_update()
    
        result = await db.execute(query)
        return result.scalar_one_or_none()
    


    @staticmethod
    async def save(
        db : AsyncSession,
        email : AuthEmail
    ) -> AuthEmail:
        db.add(email)
        await db.flush()
        return email



    @staticmethod
    async def delete(
        db : AsyncSession,
        email : AuthEmail
    ) -> None:
        await db.delete(email)
        await db.flush()
        return None
    




