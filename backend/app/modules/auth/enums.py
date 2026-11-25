"""Shared authentication domain enums; independent of persistence."""

from enum import Enum as PyEnum


class AccountType(str, PyEnum):
    USER = "user"
    STAFF = "staff"
    ADMIN = "admin"


class AccountStatus(str, PyEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class VerificationPurpose(str, PyEnum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class EmailSource(str, PyEnum):
    MANUAL = "manual"
    GOOGLE = "google"
    APPLE = "apple"


class AuthIdentityProviders(str, PyEnum):
    """States the multiple channels a user can use to authenticate."""

    PASSWORD = "password"
    GOOGLE = "google"
    APPLE = "apple"
