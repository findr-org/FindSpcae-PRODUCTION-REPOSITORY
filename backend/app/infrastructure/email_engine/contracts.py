"""Immutable email submission contracts, independent of provider APIs."""

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
