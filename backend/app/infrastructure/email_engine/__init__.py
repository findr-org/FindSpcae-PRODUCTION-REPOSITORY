"""Public interface for provider-independent transactional email delivery."""

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
