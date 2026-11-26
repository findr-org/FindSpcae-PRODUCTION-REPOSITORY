# ==========================#
# Exception_handlers.py
# ==========================#

"""
Central HTTP translation of application failures.

Responsibilities:
- Map application error categories to HTTP status codes.
- Return a consistent JSON error envelope.
- Sanitize server failures and log diagnostic error metadata.
- Register application error handling once on the FastAPI application.

Not responsible for:
- Executing business logic or deciding transaction outcomes.
- Handling engine-specific failures before service translation.
- Logging request bodies, credentials, or arbitrary exception messages.

Invariants:
- Routers do not translate ordinary application errors into HTTP responses.
- Unauthenticated responses include the Bearer challenge.
- Server error responses do not expose internal exception messages.
- Refresh-token reuse revocation is committed by the outer refresh operation,
  not by this exception handler.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.infrastructure.exceptions import ApplicationError, ErrorCategory
from app.infrastructure.logging import get_logger


logger = get_logger(__name__)

EXCEPTION_STATUS_MAP: dict[ErrorCategory, int] = {
    ErrorCategory.BAD_REQUEST: 400,
    ErrorCategory.UNAUTHENTICATED: 401,
    ErrorCategory.FORBIDDEN: 403,
    ErrorCategory.NOT_FOUND: 404,
    ErrorCategory.CONFLICT: 409,
    ErrorCategory.VALIDATION_ERROR: 422,
    ErrorCategory.RATE_LIMITED: 429,
    ErrorCategory.INTERNAL_ERROR: 500,
    ErrorCategory.SERVICE_UNAVAILABLE: 503,
}


async def application_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Translate an ApplicationError without changing transaction state."""
    if not isinstance(exc, ApplicationError):
        raise exc

    status_code = EXCEPTION_STATUS_MAP.get(exc.category, 500)
    message = exc.message
    code = exc.code

    if status_code >= 500:
        logger.error(
            "Application failure | code=%s | category=%s | status_code=%s",
            exc.code,
            exc.category.value,
            status_code,
        )
        if status_code == 503:
            message = "Service temporarily unavailable"
        else:
            code = "INTERNAL_ERROR"
            message = "An internal error occurred"

    headers = {"WWW-Authenticate": "Bearer"} if status_code == 401 else None

    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "success": False,
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register the shared application exception handler at app creation."""
    app.add_exception_handler(ApplicationError, application_exception_handler)
