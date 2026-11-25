# ==========================#
# __init__.py
# ==========================#

"""
Email Engine — Public Interface
===============================

Purpose
-------
Provides the stable import interface for business services and application startup.

Responsibilities
----------------
Exports the engine, request and submission contracts, sender and provider enums,
normalized exceptions, and the composition factory.

Boundaries
----------
Does not initialize clients, read settings, or submit messages.
"""

from .contracts import EmailRequest, EmailSubmission
from .engine import EmailEngine
from .enums import EmailProviderType, EmailSenderType
from .exceptions import (
    EmailConfigurationError,
    EmailEngineError,
    EmailRateLimitedError,
    EmailRejectedError,
    EmailSubmissionUnknownError,
    InvalidEmailRequestError,
)
from .factory import build_email_engine

__all__ = [
    "EmailEngine",
    "EmailRequest",
    "EmailSubmission",
    "EmailProviderType",
    "EmailSenderType",
    "EmailConfigurationError",
    "EmailEngineError",
    "EmailRateLimitedError",
    "EmailRejectedError",
    "EmailSubmissionUnknownError",
    "InvalidEmailRequestError",
    "build_email_engine",
]
