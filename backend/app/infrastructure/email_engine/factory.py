# ==========================#
# Factory.py
# ==========================#

"""
Email Engine — Composition Factory
==================================

Purpose
-------
Constructs the email engine from application settings and an injected HTTP client.

Responsibilities
----------------
Registers the Resend transport, applies the configured provider and timeout,
and maps SECURITY and NOTIFICATIONS to their configured sender identities.

Boundaries
----------
Does not own or close the HTTP client, perform network requests, or initialize
global engine instances. Application startup owns the client lifecycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .contracts import EmailSender
from .engine import EmailEngine
from .enums import EmailProviderType, EmailSenderType
from .providers.resend import ResendProvider

if TYPE_CHECKING:
    import httpx

    from app.infrastructure.config import Settings


def build_email_engine(settings: Settings, client: httpx.AsyncClient) -> EmailEngine:
    """Create the engine at application startup; the caller closes the client."""
    return EmailEngine(
        provider_type=settings.EMAIL_PROVIDER,
        providers={
            EmailProviderType.RESEND: ResendProvider(
                client=client,
                api_key=settings.RESEND_API_KEY.get_secret_value(),
                timeout_seconds=settings.EMAIL_TIMEOUT_SECONDS,
            ),
        },
        senders={
            EmailSenderType.SECURITY: EmailSender(
                address=settings.EMAIL_SECURITY_SENDER,
                name=settings.EMAIL_SECURITY_SENDER_NAME,
            ),
            EmailSenderType.NOTIFICATIONS: EmailSender(
                address=settings.EMAIL_NOTIFICATIONS_SENDER,
                name=settings.EMAIL_NOTIFICATIONS_SENDER_NAME,
            ),
        },
    )
