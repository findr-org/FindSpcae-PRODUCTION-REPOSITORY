"""Public interface for social identity verification."""

from .apple import AppleProvider
from .contracts import SocialVerificationRequest, VerifiedSocialIdentity
from .google import GoogleProvider

__all__ = [
    "AppleProvider",
    "GoogleProvider",
    "SocialVerificationRequest",
    "VerifiedSocialIdentity",
]
