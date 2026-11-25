"""Public exports for authentication persistence repositories.

Repository classes are stateless and accept their AsyncSession per call.
All repository module filenames are singular and mirror their model files.
"""

from .account import AuthAccountRepository
from .email import AuthEmailRepository
from .identity import AuthIdentityRepository
from .challenge import AuthVerificationChallengeRepository
from .session import AuthSessionRepository
from .refresh_token import AuthRefreshTokenRepository
from .social_challenge import AuthSocialChallengeRepository

__all__ = [
    "AuthAccountRepository",
    "AuthEmailRepository",
    "AuthIdentityRepository",
    "AuthVerificationChallengeRepository",
    "AuthSocialChallengeRepository",
    "AuthSessionRepository",
    "AuthRefreshTokenRepository",
]
