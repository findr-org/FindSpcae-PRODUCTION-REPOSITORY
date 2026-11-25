# ==========================#
# Enums.py
# ==========================#

"""
Shared domain enums for the findspace authentication module.

This module is the single source of truth for authentication account
types, account lifecycle states, verification purposes, email sources,
and authentication identity providers.

Responsibilities:
- Define consistent authentication domain values for models,
  repositories, services, schemas, and social providers.
- Keep shared domain definitions independent of persistence and
  authentication implementation details.

Not responsible for:
- Enforcing account lifecycle transitions or authorization policies.
- Verifying credentials, external identities, or email ownership.
- Defining database columns or issuing authentication tokens.

Invariants:
- Authentication components import shared enums from this module.
- This module depends only on the Python standard library.
- Persisted enum values must remain stable; changes require review
  of database mappings, migrations, and API compatibility.
"""

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
    PASSWORD = "password"
    GOOGLE = "google"
    APPLE = "apple"
