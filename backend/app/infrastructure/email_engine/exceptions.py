"""Normalized delivery errors; never include message bodies or API credentials."""


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
