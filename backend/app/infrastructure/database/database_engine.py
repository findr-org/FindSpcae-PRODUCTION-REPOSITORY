# ==========================#
# Database_engine.py
# ==========================#

"""
Asynchronous database engine management for findspace.

Responsibilities:
    - Initialize primary and optional read-replica engines.
    - Configure SQLAlchemy connection pools.
    - Reuse the primary engine when no replica is configured.
    - Expose engines to the database session layer.
    - Dispose of connection pools during application shutdown.

Database session creation and transaction management are
handled separately.
"""

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.infrastructure.config import settings


primary_database_url = settings.PRIMARY_DATABASE_URL
read_database_url = settings.READ_DATABASE_URL

if not primary_database_url:
    raise ValueError("PRIMARY_DATABASE_URL must be active for this environment")


primary_engine = create_async_engine(
    url=primary_database_url,
    echo=settings.ENV == "dev",
    pool_pre_ping=True,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
    pool_recycle=settings.DB_POOL_RECYCLE_SECONDS,
    pool_use_lifo=True,
    pool_size=settings.DB_POOL_SIZE,
)


read_engine = (
    primary_engine
    if read_database_url is None or read_database_url == primary_database_url
    else create_async_engine(
        url=read_database_url,
        echo=settings.ENV == "dev",
        pool_pre_ping=True,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
        pool_recycle=settings.DB_POOL_RECYCLE_SECONDS,
        pool_use_lifo=True,
        pool_size=settings.DB_POOL_SIZE,
    )
)


def get_primary_engine() -> AsyncEngine:
    """
    Return the primary asynchronous database engine.

    Used for write operations, authentication-sensitive queries,
    and reads requiring strong consistency.

    Returns:
        AsyncEngine: The primary SQLAlchemy database engine.
    """
    return primary_engine


def get_read_engine() -> AsyncEngine:
    """
    Return the asynchronous engine configured for read operations.

    The read engine supports queries that tolerate eventual
    consistency when a separate replica is configured.

    If no distinct replica URL exists, the primary engine is
    reused without creating an additional connection pool.

    Returns:
        AsyncEngine: The read engine or the primary engine
        when no separate replica is configured.
    """
    return read_engine


async def dispose_database_engines() -> None:
    """
    Dispose of database connection pools during application shutdown.

    The read engine is disposed of separately only when it is
    distinct from the primary engine.

    The primary engine is always disposed of, even if disposing
    the read engine raises an exception.

    This function should be invoked during FastAPI lifespan
    shutdown after active database operations have completed.
    """
    try:
        if read_engine is not primary_engine:
            await read_engine.dispose()
    finally:
        await primary_engine.dispose()
