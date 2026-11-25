# ==========================#
# Exceptions.py
# ==========================#

"""
Email Engine — Exceptions
=========================

Purpose
-------
Defines normalized failures exposed by the email infrastructure to its callers.

Responsibilities
----------------
Distinguishes configuration and request errors, explicit provider rejection,
rate limiting, and uncertain submission outcomes. An uncertain outcome means
acceptance could not be established and must not trigger blind retries.

Boundaries
----------
Exception messages must not expose API credentials, OTPs or message bodies.
"""


class EmailEngineError(Exception):
    """Base exception for email infrastructure failures."""


class EmailConfigurationError(EmailEngineError):
    """Required provider or sender configuration is unavailable."""


class InvalidEmailRequestError(EmailEngineError):
    """Message cannot be submitted because its input is invalid."""


class EmailRejectedError(EmailEngineError):
    """Provider explicitly rejected the submission."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Email provider rejected submission (HTTP {status_code})")


class EmailRateLimitedError(EmailRejectedError):
    """Provider explicitly rate-limited the submission."""


class EmailSubmissionUnknownError(EmailEngineError):
    """Acceptance is uncertain; do not blindly retry or fail over."""
