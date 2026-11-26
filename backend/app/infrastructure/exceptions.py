# ==========================#
# Exceptions.py
# ==========================#

"""
Shared application exception contract for findspace.

Responsibilities:
- Classify expected application failures using common error categories.
- Carry stable machine-readable error codes and safe public messages.
- Provide a shared code for refresh-token reuse transaction handling.

Not responsible for:
- HTTP status mapping, response serialization, or logging.
- Committing or rolling back transactions.
- Defining internal engine or provider failures.

Invariants:
- All services use ApplicationError rather than domain-specific subclasses.
- Codes and messages must not contain credentials or sensitive internal details.
- Error codes used by callers must remain stable.
"""

from enum import Enum


class ErrorCategory(str, Enum):
    """Transport-independent categories for application failures."""

    BAD_REQUEST = "bad_request"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    VALIDATION_ERROR = "validation_error"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
    SERVICE_UNAVAILABLE = "service_unavailable"


# The refresh transaction recognizes this code only after revocation is saved.
# It must commit that revocation before propagating the failure.
REFRESH_TOKEN_REUSE = "REFRESH_TOKEN_REUSE"


class ApplicationError(Exception):
    """An expected application failure with a safe public error contract."""

    def __init__(
        self,
        category: ErrorCategory,
        code: str,
        message: str,
    ) -> None:
        self.category = category
        self.code = code
        self.message = message
        super().__init__(message)
