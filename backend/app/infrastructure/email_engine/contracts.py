# ==========================#
# Contracts.py
# ==========================#

"""
Email Engine — Internal Contracts
=================================

Purpose
-------
Defines immutable data structures exchanged between services, the engine,
and concrete email transports.

Responsibilities
----------------
EmailRequest carries a logical sender, recipient, subject and message bodies.
EmailSender carries the resolved address and display name. EmailSubmission
carries the provider and its acceptance identifier. Message bodies are excluded
from request representations to reduce accidental exposure of OTPs.

Boundaries
----------
Does not validate messages, communicate with providers, or confirm inbox delivery.
"""

from dataclasses import dataclass, field

from .enums import EmailProviderType, EmailSenderType


@dataclass(frozen=True, slots=True)
class EmailRequest:
    """Business message; bodies are excluded from repr to protect secrets."""

    sender: EmailSenderType
    recipient: str
    subject: str
    text_body: str | None = field(default=None, repr=False)
    html_body: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class EmailSender:
    """Resolved sender identity supplied to the concrete transport."""

    address: str
    name: str


@dataclass(frozen=True, slots=True)
class EmailSubmission:
    """Provider acceptance receipt, not confirmation of inbox delivery."""

    provider: EmailProviderType
    message_id: str
