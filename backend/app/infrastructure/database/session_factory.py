# ==========================#
# Session_factory.py
# ==========================#

"""
Asynchronous database session management for findspace.

This module creates and provides SQLAlchemy asynchronous
database sessions for primary and read operations.

Responsibilities:
    - Configure primary and read database session factories.
    - Provide sessions for writes and strongly consistent reads.
    - Provide sessions for replica-eligible read operations.
    - Support primary-engine fallback when no replica is configured.
    - Handle session cleanup and rollback on errors.
    - Expose reusable FastAPI session dependencies.

Transaction commits are controlled explicitly by the service layer.

Database engine initialization, connection pooling, and disposal
are handled separately by the database_engine module.
"""

from typing import Annotated, AsyncGenerator, TypeAlias

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.infrastructure.database.database_engine import (
    get_primary_engine,
    get_read_engine,
)


# ==========================================
# SESSION FACTORIES
# ==========================================

PrimaryEngineLocal = async_sessionmaker(
    bind=get_primary_engine(),
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=True,
)


ReadEngineLocal = async_sessionmaker(
    bind=get_read_engine(),
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=True,
)


# ==========================================
# PRIMARY DATABASE DEPENDENCY
# ==========================================


async def get_primary_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield a session bound to the primary database engine.

    Intended for write operations, authentication-sensitive
    queries, and reads requiring strong consistency.

    The service layer is responsible for committing transactions.
    Uncommitted changes are rolled back when the session closes.
    """

    async with PrimaryEngineLocal() as db:
        try:
            yield db
        except Exception:
            await db.rollback()
            raise


# ==========================================
# READ DATABASE DEPENDENCY
# ==========================================


async def get_read_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield a session bound to the configured read engine.

    Intended for read operations that tolerate eventual
    consistency.

    When no separate replica exists, the primary engine
    is used automatically.

    This dependency does not enforce read-only permissions.
    Any unfinished transaction is rolled back on session close.
    """

    async with ReadEngineLocal() as db:
        try:
            yield db
        except Exception:
            await db.rollback()
            raise


# ==========================================
# FASTAPI SESSION DEPENDENCY ALIASES
# ==========================================

primaryDbSession: TypeAlias = Annotated[
    AsyncSession,
    Depends(get_primary_db),
]

readDbSession: TypeAlias = Annotated[
    AsyncSession,
    Depends(get_read_db),
]
