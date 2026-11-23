# ==========================#
# Base.py
# ==========================#

"""
SQLAlchemy declarative base and reusable model mixins for findspace.

This module defines the shared ORM metadata registry and common
model attributes inherited by application database models.

Responsibilities:
    - Provide a common declarative base for SQLAlchemy models.
    - Define reusable UUID primary-key columns.
    - Define automatic creation and modification timestamps.
    - Provide an abstract base model combining these features.

Database schema creation and evolution are managed through
Alembic migrations.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, UUID, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Root declarative base for all SQLAlchemy ORM models.

    Maintains the shared metadata registry used to define
    database tables and generate Alembic migrations.
    """

    pass


def utc_now() -> datetime:
    """
    Return the current timezone-aware UTC datetime.

    Used as an application-side default for timestamp columns.
    """
    return datetime.now(timezone.utc)


class UUIDMixin:
    """
    Provide a UUID primary key for inheriting models.

    UUID values are generated automatically when SQLAlchemy
    inserts a new record without an explicitly assigned ID.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )


class TimeStampMixin:
    """
    Provide automatic creation and modification timestamps.

    Attributes:
        created_at: UTC timestamp assigned when a row is created.
        updated_at: UTC timestamp assigned when a row is created
            and updated during subsequent SQLAlchemy updates.

    Python-side defaults generate timestamps during SQLAlchemy
    operations. Server defaults support inserts performed
    without application-supplied timestamps.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
        onupdate=utc_now,
    )


class BaseModel(UUIDMixin, TimeStampMixin, Base):
    """
    Abstract parent class for application ORM models.

    Combines UUID primary keys and audit timestamps into
    a reusable foundation for concrete database models.

    This class does not create its own database table.
    Subclasses must declare their respective table names.
    """

    __abstract__ = True
