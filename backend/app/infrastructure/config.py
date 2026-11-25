# ==========================#
# Config.py
# ==========================#

"""
This file is solely responsible for handling and validating
Application configuration variables
"""

from pydantic import Field, field_validator, model_validator
from urllib.parse import urlsplit
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from typing import Literal
from enum import Enum as PyEnum
from functools import lru_cache
from pathlib import Path

from pydantic_settings import SettingsConfigDict, BaseSettings
from pydantic import SecretStr


class Environment(str, PyEnum):
    """Environment Type Enum"""

    DEVELOPMENT = "dev"
    STAGING = "stg"
    PRODUCTION = "prod"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # ==========================#
    # BASIC APP CONFIGURATION
    # ==========================#
    APP_NAME: str
    ENV: Environment = Environment.DEVELOPMENT
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] | None = None

    # ==========================#
    # DATABASE CONFIGURATION
    # ==========================#
    PRIMARY_DATABASE_URL: str
    READ_DATABASE_URL: str | None = None

    DB_POOL_SIZE: int = Field(default=5, ge=1, le=50)
    DB_MAX_OVERFLOW: int = Field(default=5, ge=0, le=100)
    DB_POOL_TIMEOUT_SECONDS: int = Field(default=10, ge=1, le=120)
    DB_POOL_RECYCLE_SECONDS: int = Field(default=1800, ge=60)

    # ==========================#
    # REDIS CONFIGURATION
    # ==========================#
    REDIS_URL: str | None = None
    CACHE_ENABLED: bool = False

    # ==========================#
    # SECURITY TOKEN CONFIGUATION
    # ==========================#
    SECRET_KEY: SecretStr = Field(..., min_length=32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 5
    ALGORITHM: Literal["HS256"] = "HS256"
    DEFAULT_SESSION_DAYS: int = Field(default=7, gt=0)
    REMEMBER_ME_SESSION_DAYS: int = Field(default=30, gt=0)

    # ==============================#
    # SOCIAL PROVIDER CONFIGURATION
    # ===============================#
    GOOGLE_CLIENT_IDS: list[str]
    APPLE_CLIENT_IDS: list[str]

    # ==========================#
    # CORS CONFIGURATION
    # ==========================#

    ALLOWED_ORIGINS: list[str] = Field(default_factory=list)

    @field_validator("PRIMARY_DATABASE_URL", "READ_DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, value):
        if value is None or value == "":
            return None

        try:
            url = make_url(value)
        except (ArgumentError, TypeError) as exc:
            raise ValueError("Invalid PostgreSQL database URL") from exc

        if url.drivername not in ("postgres", "postgresql", "postgresql+asyncpg"):
            raise ValueError("Only PostgreSQL asyncpg URLs are supported")
        if not url.host or not url.database:
            raise ValueError("Database URL must include a host and database")

        return url.set(drivername="postgresql+asyncpg").render_as_string(
            hide_password=False
        )

    @field_validator("REDIS_URL")
    @classmethod
    def validate_redis_url(cls, value):
        if value is None or value == "":
            return None

        try:
            parsed = urlsplit(value)
            if parsed.scheme not in ("redis", "rediss") or not parsed.hostname:
                raise ValueError("Redis URL must use redis:// or rediss:// with a host")
            _ = parsed.port  # Reject invalid port values.
        except ValueError as exc:
            raise ValueError("Invalid Redis URL") from exc

        return value

    @model_validator(mode="after")
    def validate_cache_config(self):
        if self.CACHE_ENABLED and not self.REDIS_URL:
            raise ValueError("REDIS_URL is required when CACHE_ENABLED is True")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # pyright: ignore[reportCallIssue]


settings = get_settings()
