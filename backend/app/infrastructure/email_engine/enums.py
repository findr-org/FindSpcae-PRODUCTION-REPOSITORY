"""Shared email delivery categories and supported transport providers."""

from enum import Enum


class EmailProviderType(str, Enum):
    """Transport selected by deployment configuration, not business services."""

    RESEND = "resend"


class EmailSenderType(str, Enum):
    """Logical sender categories resolved to configured addresses by the engine."""

    SECURITY = "security"
    NOTIFICATIONS = "notifications"
