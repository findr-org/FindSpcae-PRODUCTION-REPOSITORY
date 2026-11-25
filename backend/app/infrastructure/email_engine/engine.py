# ==========================#
# Engine.py
# ==========================#

"""
Email Engine — Delivery Engine
==============================

Purpose
-------
Acts as the provider-independent entry point for outgoing transactional email.

Responsibilities
----------------
Selects the configured provider during initialization, resolves logical sender
categories to configured identities, validates recipient, subject and body,
and delegates each submission once to the selected transport.

Boundaries
----------
Does not generate OTPs, compose business messages, manage database transactions,
retry ambiguous submissions, or guarantee inbox delivery.
"""

from collections.abc import Mapping

from .base import BaseEmailProvider
from .contracts import EmailRequest, EmailSender, EmailSubmission
from .enums import EmailProviderType, EmailSenderType
from .exceptions import EmailConfigurationError, InvalidEmailRequestError


class EmailEngine:
    """Central entry point for transactional email submission."""

    def __init__(
        self,
        provider_type: EmailProviderType,
        providers: Mapping[EmailProviderType, BaseEmailProvider],
        senders: Mapping[EmailSenderType, EmailSender],
    ) -> None:
        if provider_type not in providers:
            raise EmailConfigurationError("Configured email provider is unavailable")
        if any(sender not in senders for sender in EmailSenderType):
            raise EmailConfigurationError("Required email sender is not configured")
        self._provider = providers[provider_type]
        self._senders = dict(senders)

    async def send(self, request: EmailRequest) -> EmailSubmission:
        """Validate a message, resolve its sender and submit it once."""
        recipient = request.recipient
        if (
            not isinstance(recipient, str)
            or recipient.count("@") != 1
            or not all(recipient.split("@"))
            or any(char.isspace() or char in "<>,;" for char in recipient)
        ):
            raise InvalidEmailRequestError("Invalid recipient address")
        if (
            not isinstance(request.subject, str)
            or not request.subject.strip()
            or any(char in request.subject for char in "\r\n")
        ):
            raise InvalidEmailRequestError("Invalid email subject")
        bodies = (request.text_body, request.html_body)
        if any(body is not None and not isinstance(body, str) for body in bodies):
            raise InvalidEmailRequestError("Invalid email body")
        if not any(body and body.strip() for body in bodies):
            raise InvalidEmailRequestError("Email requires a text or HTML body")
        if not isinstance(request.sender, EmailSenderType):
            raise InvalidEmailRequestError("Unknown email sender category")

        return await self._provider.send(request, self._senders[request.sender])
