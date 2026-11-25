# ==========================#
# Base.py
# ==========================#

"""
Social Authentication Engine — Base Provider
============================================

Purpose
-------
Defines the common interface for external identity providers
such as Google and Apple.

The social authentication engine verifies externally issued
identity tokens and converts verified claims into a consistent
internal identity representation.

Architecture
------------
Each provider implements a shared abstract interface while
handling its own provider-specific verification requirements.

The engine is responsible for:
- Verifying external JWT signatures.
- Validating issuer, audience, expiration, and subject claims.
- Validating authentication nonces when required.
- Retrieving trusted public signing keys.
- Managing JWKS caching and key rotation.
- Returning normalized, verified identity information.
- Raising consistent verification exceptions.

The base provider defines the verification contract.
Concrete providers implement verification using their
respective identity provider's specifications.

Boundaries
----------
The social authentication engine must not:
- Access application databases.
- Create or update user accounts.
- Link external identities to existing accounts.
- Generate findspace access or refresh tokens.
- Manage authentication sessions.
- Make application authorization decisions.

These responsibilities belong to the authentication services.

Provider Contract
-----------------
Every provider must expose an asynchronous verification operation
that accepts a SocialVerificationRequest and returns a
VerifiedSocialIdentity.

A verified identity must only be returned after successful
signature and claims validation.

Verification failures must raise appropriate exceptions.

Related Components
------------------
contracts.py  : Internal verification request and result contracts.
jwks.py       : Public-key retrieval, caching, and rotation.
google.py     : Google-specific verification implementation.
apple.py      : Apple-specific verification implementation.
exceptions.py : Standardized verification errors.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .contracts import SocialVerificationRequest, VerifiedSocialIdentity


class BaseSocialProvider(ABC):
    @abstractmethod
    async def verify(
        self, request: SocialVerificationRequest
    ) -> VerifiedSocialIdentity:
        pass
