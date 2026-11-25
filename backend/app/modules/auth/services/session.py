# ==========================#
# Session.py
# ==========================#

"""
Authentication session lifecycle service.

This module orchestrates the creation, validation, renewal,
and revocation of authentication sessions within findspace.

It coordinates account persistence, session persistence,
refresh-token persistence, and security utilities to manage
authenticated sessions across multiple devices and clients.

Responsibilities:
- Establish authenticated sessions for eligible accounts.
- Generate and issue access and refresh token pairs.
- Validate session state and account eligibility.
- Rotate refresh tokens following successful refresh requests.
- Extend session expiration using sliding expiration policies.
- Detect refresh-token reuse and revoke compromised sessions.
- Revoke individual or multiple authentication sessions.
- Retrieve account sessions for device management.
- Coordinate atomic session and refresh-token operations.

Not responsible for:
- Verifying passwords or external authentication providers.
- Registering authentication accounts.
- Managing user profiles, onboarding, or KYC.
- Determining caller permissions or resource ownership.
- Extracting credentials from HTTP requests.
- Managing HTTP responses or cookies.
- Enforcing request rate limits.
- Executing database queries directly.

Invariants:
- Every session must belong to an eligible authentication account.
- An account may have multiple independent sessions.
- Plaintext refresh tokens must never be persisted.
- Each session may have at most one unconsumed refresh token.
- Refresh tokens must be consumed before issuing replacements.
- Expired or revoked sessions cannot be renewed.
- Refresh-token rotation and session renewal must be atomic.
- Refresh-token reuse must trigger session compromise handling.
- Security-sensitive session operations must use the primary database.
- Session revocation must not delete token rotation history.
- Services must remain independent of HTTP and authorization policies.
"""