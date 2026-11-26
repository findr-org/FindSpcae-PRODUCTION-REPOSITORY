# ==========================#
# Verification.py
# ==========================#

"""
Authentication verification challenge data contracts.

This module defines the structured input and output schemas
used by the authentication verification service.

These schemas establish explicit data contracts between
the verification service and its consumers, including
registration, password recovery, and email management services.

Responsibilities:
- Define verification challenge issuance input contracts.
- Define verification challenge resend input contracts.
- Define verification code submission contracts.
- Define individual and bulk challenge invalidation contracts.
- Define verification challenge metadata response contracts.
- Define successful verification response contracts.
- Validate input structure, types, and field constraints.
- Provide consistent serialization of verification information.

Not responsible for:
- Generating, hashing, or validating verification codes.
- Creating or invalidating verification challenges.
- Enforcing challenge expiration and attempt limits.
- Enforcing verification code resend cooldowns.
- Delivering verification emails.
- Executing database operations.
- Managing authentication account state.
- Determining caller permissions or resource ownership.
- Managing HTTP requests or responses.
- Executing verification business logic.

Invariants:
- Schema validation must remain independent of database state.
- Verification challenge identifiers must use UUIDs.
- Verification purposes must use the supported purpose enum.
- Verification timestamps must be timezone-aware.
- Verification attempt counts must be nonnegative.
- Plaintext verification codes may only appear in designated
  verification submission input contracts.
- Plaintext verification codes must never appear in responses.
- Stored verification code hashes must never appear in responses.
- Unexpected input and output fields must be rejected.
- Schemas must remain independent of HTTP transport details.
"""
from __future__ import annotations
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel , ConfigDict

from app.modules.auth.enums import VerificationPurpose

class InputBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )


class OutputBase(BaseModel):
    model_config = ConfigDict(
        use_enum_values=True,
        extra="forbid",
    )



class VerificationChallengeIssueRequest(InputBase):
    email_id : UUID
    purpose : VerificationPurpose



class VerificationChallengeResponse(OutputBase):
    challenge_id : UUID
    email_id : UUID
    purpose : VerificationPurpose
    expires_at : datetime
    resend_available_at : datetime
