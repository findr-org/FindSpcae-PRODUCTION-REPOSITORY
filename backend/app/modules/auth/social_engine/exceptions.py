# ==========================#
# Exceptions.py
# ==========================#


"""
Social Authentication Engine — Exceptions
=========================================

Defines standardized exceptions raised during external identity
token verification for Google and Apple.

All social providers share this exception hierarchy, allowing
authentication services to handle verification failures without
depending on provider-specific implementations.

Exceptions
----------
SocialEngineError:
    Base exception for social authentication engine failures.

InvalidSocialTokenError:
    Raised when a token is malformed, has an invalid signature,
    contains invalid claims, or fails nonce verification.

ExpiredSocialTokenError:
    Raised when an external identity token has expired.

SocialProviderUnavailableError:
    Raised when the provider's verification infrastructure is
    unavailable and token verification cannot be completed.

Security
--------
- Never include raw identity tokens in exception messages.
- Never expose sensitive verification details.
- Fail securely when token authenticity cannot be established.
- Keep HTTP response handling outside the social engine.
"""


class SocialEngineError(Exception):
    """Base exception for all social authentication engine failures."""

    pass


class InvalidSocialTokenError(SocialEngineError):
    """Raised when an external identity token fails verification."""

    pass


class ExpiredSocialTokenError(InvalidSocialTokenError):
    """Raised when an external identity token has expired."""

    pass


class SocialProviderUnavailableError(SocialEngineError):
    """Raised when trusted provider verification services are unavailable."""

    pass
