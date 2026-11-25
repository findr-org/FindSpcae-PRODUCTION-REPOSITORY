# ==========================#
# Base.py
# ==========================#

"""
Email Engine — Base Provider
============================

Purpose
-------
Defines the common asynchronous transport interface implemented by email providers.

Responsibilities
----------------
Accepts an internal EmailRequest and a resolved EmailSender. Implementations
return EmailSubmission after provider acceptance or raise normalized errors.

Boundaries
----------
Does not select providers, resolve sender categories, or generate email content.
"""

from abc import ABC, abstractmethod

from .contracts import EmailRequest, EmailSender, EmailSubmission


class BaseEmailProvider(ABC):
    """Submit a resolved message and return a normalized acceptance receipt."""

    @abstractmethod
    async def send(
        self, request: EmailRequest, sender: EmailSender
    ) -> EmailSubmission:
        raise NotImplementedError
