"""
Social Authentication Engine — Internal Contracts
=================================================

Defines immutable internal data contracts for Google and Apple
identity verification.

SocialVerificationRequest carries the identity token and trusted
verification context.

VerifiedSocialIdentity contains normalized identity information
returned after successful signature and claims verification.

This module does not perform token verification, database operations,
nonce management, or application session management.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.modules.auth.models.identity import AuthIdentityProviders


@dataclass(frozen=True, slots=True)
class SocialVerificationRequest:
    """Input data required for social identity verification."""

    id_token: str
    expected_nonce: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedSocialIdentity:
    """Normalized identity returned after successful verification."""

    provider: AuthIdentityProviders
    subject: str
    email_verified: bool
    email: str | None = None
    display_name: str | None = None
    picture_url: str | None = None
