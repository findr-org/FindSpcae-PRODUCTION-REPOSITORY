"""
Public exports and ORM registration for findspace authentication models.

Importing this package registers all authentication models with 
SQLAlchemy's shared declarative metadata

This module also exposes model classes and enums through a 
single import interface for services , schemas  and migrations
"""

from .account import(
    AuthAccount,
    AccountType,
    AccountStatus
)


from .email import(
    AuthEmail,
    EmailSource
)


from .identity import(
    AuthIdentity,
    AuthIdentityProviders
)

from .challenge import(
    AuthVerificationChallenge,
    VerificationPurpose
)



from .session import AuthSession
from .refresh_token import AuthRefreshToken




#==========================#
#PUBLIC EXPORTS
#==========================#

__all__ = [
    # Models
    "AuthAccount",
    "AuthEmail",
    "AuthIdentity",
    "AuthVerificationChallenge",
    "AuthSession",
    "AuthRefreshToken",



    # Enums
    "AccountType",
    "AccountStatus",
    "EmailSource",
    "AuthIdentityProviders",
    "VerificationPurpose"
]