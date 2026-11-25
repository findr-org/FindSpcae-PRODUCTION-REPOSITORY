"""Transport interface implemented by each external email provider."""

from abc import ABC, abstractmethod

from .contracts import EmailRequest, EmailSender, EmailSubmission


class BaseEmailProvider(ABC):
    """Submit a resolved message and return a normalized acceptance receipt."""

    @abstractmethod
    async def send(
        self, request: EmailRequest, sender: EmailSender
    ) -> EmailSubmission:
        raise NotImplementedError
