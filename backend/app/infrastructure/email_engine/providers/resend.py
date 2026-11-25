# ==========================#
# Resend.py
# ==========================#

"""
Email Engine — Resend Provider
==============================

Purpose
-------
Implements the shared email transport contract using Resend's REST API.

Responsibilities
----------------
Builds the provider payload, authenticates with a Bearer API key, submits via
an injected HTTPX AsyncClient to POST https://api.resend.com/emails, and
normalizes the response into an acceptance receipt or infrastructure exception.

Boundaries
----------
Does not use the Resend SDK, own the HTTP client, select sender categories,
log sensitive message content, or automatically retry ambiguous submissions.
"""

import httpx

from ..base import BaseEmailProvider
from ..contracts import EmailRequest, EmailSender, EmailSubmission
from ..enums import EmailProviderType
from ..exceptions import (
    EmailConfigurationError,
    EmailRateLimitedError,
    EmailRejectedError,
    EmailSubmissionUnknownError,
)

RESEND_EMAIL_URL = "https://api.resend.com/emails"


class ResendProvider(BaseEmailProvider):
    """Translate internal email contracts to Resend's HTTP API.

    The caller owns the HTTP client's lifecycle. No automatic retries are
    performed because a timed-out submission may already have been accepted.
    """

    def __init__(
        self, client: httpx.AsyncClient, api_key: str, timeout_seconds: float = 10
    ) -> None:
        if not api_key.strip() or timeout_seconds <= 0:
            raise EmailConfigurationError("Invalid Resend configuration")
        self._client = client
        self._api_key = api_key
        self._timeout = httpx.Timeout(timeout_seconds)

    async def send(self, request: EmailRequest, sender: EmailSender) -> EmailSubmission:
        payload: dict[str, str | list[str]] = {
            "from": f"{sender.name} <{sender.address}>",
            "to": [request.recipient],
            "subject": request.subject,
        }
        if request.text_body is not None:
            payload["text"] = request.text_body
        if request.html_body is not None:
            payload["html"] = request.html_body

        try:
            response = await self._client.post(
                RESEND_EMAIL_URL,
                headers={"Authorization": f"Bearer {self._api_key}"},
                json=payload,
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.RequestError:
            raise EmailSubmissionUnknownError(
                "Resend submission outcome is unknown"
            ) from None

        if response.status_code == 429:
            raise EmailRateLimitedError(429)
        if response.status_code >= 500 or response.status_code == 408:
            raise EmailSubmissionUnknownError("Resend submission outcome is unknown")
        if not response.is_success:
            raise EmailRejectedError(response.status_code)

        try:
            data = response.json()
        except ValueError:
            raise EmailSubmissionUnknownError(
                "Invalid Resend acceptance receipt"
            ) from None

        message_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(message_id, str) or not message_id.strip():
            raise EmailSubmissionUnknownError("Missing Resend message identifier")

        return EmailSubmission(provider=EmailProviderType.RESEND, message_id=message_id)
