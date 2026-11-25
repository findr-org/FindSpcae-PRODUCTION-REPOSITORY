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
    """
    Classifies an authentication account by its domain.

    USER represents marketplace accounts, STAFF represents operational
    staff accounts, and ADMIN represents administrator accounts.
    Account type alone does not define individual permissions.
    """

    USER = "user"
    STAFF = "staff"
    ADMIN = "admin"


class AccountStatus(str, PyEnum):
    """
    Represents the lifecycle state of an authentication account.

    PENDING: Account activation is incomplete.
    ACTIVE: Account is eligible for authentication.
    SUSPENDED: Account access is suspended.
    DISABLED: Account access is disabled.

    State transitions and authentication eligibility are enforced
    by the authentication service, not by this enum.
    """

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class VerificationPurpose(str, PyEnum):
    """
    Identifies the operation a verification challenge authorizes.

    EMAIL_VERIFICATION proves email ownership; PASSWORD_RESET
    authorizes password recovery. Challenges must be validated
    against their intended purpose before consumption.
    """

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class EmailSource(str, PyEnum):
    """
    Records the original source of an authentication email address.

    MANUAL identifies an address supplied directly by the user.
    GOOGLE and APPLE identify addresses obtained from those providers.
    Source does not establish verification or password-login eligibility.
    """

    MANUAL = "manual"
    GOOGLE = "google"
    APPLE = "apple"


class AuthIdentityProviders(str, PyEnum):
    """
    Identifies the credential or external provider used to authenticate.

    PASSWORD represents local password authentication.
    GOOGLE and APPLE represent external identity providers.

    Provider identity is distinct from email source and does not
    authorize automatic account linking by matching email addresses.
    """

    PASSWORD = "password"
    GOOGLE = "google"
    APPLE = "apple"
