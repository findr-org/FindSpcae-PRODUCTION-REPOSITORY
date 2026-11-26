# ==========================#
# Session.py
# ==========================#

"""
Authentication session data contracts.

This module defines the structured input and output schemas
used by the authentication session service.

These schemas establish explicit data contracts between
the session service and its consumers, including other
authentication services and API route handlers.

Responsibilities:
- Define session creation input contracts.
- Define refresh-token submission contracts.
- Define access and refresh token response contracts.
- Define session metadata response contracts.
- Define account session listing response contracts.
- Validate input structure, types, and field constraints.
- Provide consistent serialization of session information.

Not responsible for:
- Creating or validating authentication sessions.
- Generating, hashing, or rotating tokens.
- Executing database operations.
- Enforcing account eligibility or authorization policies.
- Determining session expiration policies.
- Managing HTTP requests, responses, or cookies.
- Executing authentication business logic.

Invariants:
- Schema validation must remain independent of database state.
- Stored refresh-token hashes must never appear in responses.
- Passwords and password hashes must never appear in session responses.
- Plaintext refresh tokens may only appear in designated
  credential input and token issuance contracts.
- Sensitive credential fields must be excluded from
  diagnostic representations where applicable.
- Session identifiers must use UUIDs.
- Session timestamps must be timezone-aware.
- Optional client metadata must respect defined field constraints.
- Schemas must remain independent of HTTP transport details.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.modules.auth.enums import AccountType


class InputBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OutputBase(BaseModel):
    model_config = ConfigDict(use_enum_values=True, extra="forbid")


class SessionCreateRequest(InputBase):
    account_id: UUID
    device_name: str | None = Field(max_length=120, default=None)
    user_agent: str | None = Field(max_length=512, default=None)
    remember_me: bool = False


class TokenPairResponse(OutputBase):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    session_id: UUID
    expires_in: int = Field(gt=0)
    session_expires_at: datetime


class SessionRefreshRequest(InputBase):
    refresh_token: str = Field(min_length=1, max_length=512)


class SessionValidationRequest(InputBase):
    account_id: UUID
    session_id: UUID


class SessionValidationResponse(OutputBase):
    account_id: UUID
    session_id: UUID
    account_type: AccountType
    session_expires_at: datetime


class SessionRevokeRequest(InputBase):
    session_id: UUID


class SessionRevokeAllRequest(InputBase):
    account_id: UUID


class SessionRevokeAllResponse(OutputBase):
    account_id: UUID
    revoked_count: int = Field(ge=0)


class SessionRevokeOtherRequest(InputBase):
    account_id: UUID
    current_session_id: UUID


class SessionRevokeOtherResponse(OutputBase):
    account_id: UUID
    current_session_id: UUID
    revoked_count: int = Field(ge=0)


class SessionListRequest(InputBase):
    account_id: UUID
    current_session_id: UUID
    active_only: bool = True
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class SessionResponse(OutputBase):
    session_id: UUID
    device_name: str | None
    user_agent: str | None
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    is_current: bool
    is_active: bool


class SessionListResponse(OutputBase):
    """A page of sessions and account-wide counts, independent of filtering."""

    account_id: UUID
    sessions: list[SessionResponse]
    total_count: int = Field(ge=0)
    active_count: int = Field(ge=0)
    limit: int
    offset: int
    active_only: bool
