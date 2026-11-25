# ==========================#
# Enums.py
# ==========================#

"""
Email Engine — Shared Enums
===========================

Purpose
-------
Defines the shared email infrastructure categories independently of provider APIs.

Responsibilities
----------------
EmailProviderType identifies supported delivery transports. Resend is the only
MVP transport. EmailSenderType identifies SECURITY and NOTIFICATIONS senders;
actual addresses and display names are resolved from deployment configuration.

Boundaries
----------
Does not store credentials, addresses, or provider selection logic.
"""

from enum import Enum


class EmailProviderType(str, Enum):
    """Transport selected by deployment configuration, not business services."""

    RESEND = "resend"


class EmailSenderType(str, Enum):
    """Logical sender categories resolved to configured addresses by the engine."""

    SECURITY = "security"
    NOTIFICATIONS = "notifications"
