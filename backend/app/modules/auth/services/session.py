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

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.config import settings
from app.infrastructure.exceptions import (
    REFRESH_TOKEN_REUSE,
    ApplicationError,
    ErrorCategory,
)
from app.infrastructure.logging import get_logger
from app.infrastructure.security import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from app.modules.auth.enums import AccountStatus
from app.modules.auth.models import AuthRefreshToken, AuthSession
from app.modules.auth.repositories import (
    AuthAccountRepository,
    AuthRefreshTokenRepository,
    AuthSessionRepository,
)
from app.modules.auth.schemas import (
    SessionCreateRequest,
    SessionRefreshRequest,
    SessionRevokeAllRequest,
    SessionRevokeAllResponse,
    SessionRevokeRequest,
    SessionValidationRequest,
    SessionValidationResponse,
    TokenPairResponse,
)
from backend.app.modules.auth.schemas.session import SessionRevokeOtherRequest

logger = get_logger(__name__)


class SessionService:
    """
    Orchestrates the lifecycle of authentication sessions,
    including session creation, validation, renewal,
    token issuance, and revocation.
    """

    @staticmethod
    async def create_session(
        db: AsyncSession,
        payload: SessionCreateRequest,
    ) -> TokenPairResponse:
        authenticated_account = await AuthAccountRepository.get_by_id(
            db=db,
            account_id=payload.account_id,
            lock=True,
        )

        if authenticated_account is None:
            raise ApplicationError(
                category=ErrorCategory.NOT_FOUND,
                code="ACCOUNT_NOT_FOUND",
                message="Account does not exist",
            )

        if authenticated_account.status != AccountStatus.ACTIVE:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="ACCOUNT_INACTIVE",
                message="Account is inactive",
            )

        session_days = (
            settings.REMEMBER_ME_SESSION_DAYS
            if payload.remember_me
            else settings.DEFAULT_SESSION_DAYS
        )

        now = datetime.now(timezone.utc)

        expires_at = now + timedelta(days=session_days)

        session = AuthSession(
            account_id=authenticated_account.id,
            last_activity_at=now,
            expires_at=expires_at,
            device_name=payload.device_name,
            user_agent=payload.user_agent,
        )

        session = await AuthSessionRepository.create(
            db=db,
            session=session,
        )

        generated_refresh_token = generate_refresh_token()

        hashed_token = hash_refresh_token(generated_refresh_token)

        refresh_token = AuthRefreshToken(
            session_id=session.id,
            token_hash=hashed_token,
            expires_at=session.expires_at,
        )

        await AuthRefreshTokenRepository.create(
            db=db,
            token=refresh_token,
        )

        claims = {
            "sub": str(authenticated_account.id),
            "sid": str(session.id),
        }

        access_token_duration = timedelta(
            minutes=(
                60
                if settings.ENV == "dev"
                else settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        )

        access_token = create_access_token(
            claims,
            expires_delta=access_token_duration,
        )

        token_pair_response = TokenPairResponse(
            access_token=access_token,
            refresh_token=generated_refresh_token,
            session_id=session.id,
            expires_in=int(access_token_duration.total_seconds()),
            session_expires_at=session.expires_at,
        )

        logger.info(
            "Session prepared successfully | session_id=%s | account_id=%s",
            session.id,
            authenticated_account.id,
        )

        return token_pair_response

    @staticmethod
    async def refresh_session(
        db: AsyncSession,
        payload: SessionRefreshRequest,
    ) -> TokenPairResponse:
        refresh_token = payload.refresh_token

        hashed_token = hash_refresh_token(refresh_token)

        token_record = await AuthRefreshTokenRepository.get_by_hash(
            db=db,
            token_hash=hashed_token,
            lock=False,
        )

        if token_record is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token is invalid",
            )

        session = await AuthSessionRepository.get_by_id(
            db=db,
            session_id=token_record.session_id,
            lock=False,
        )

        if session is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token is invalid",
            )

        # Acquire account lock
        account = await AuthAccountRepository.get_by_id(
            db=db,
            account_id=session.account_id,
            lock=True,
        )

        if account is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token is invalid",
            )

        # Acquire session lock
        session = await AuthSessionRepository.get_by_id(
            db=db,
            session_id=session.id,
            lock=True,
        )

        if session is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token is invalid",
            )

        # Acquire refresh-token lock
        token_record = await AuthRefreshTokenRepository.get_by_hash(
            db=db,
            token_hash=hashed_token,
            lock=True,
        )

        if token_record is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token is invalid",
            )

        now = datetime.now(timezone.utc)

        # Validate record associations
        if (
            session.account_id != account.id
            or token_record.session_id != session.id
        ):
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token is invalid",
            )

        # Validate account and session eligibility
        if account.status != AccountStatus.ACTIVE:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="ACCOUNT_INACTIVE",
                message="Account is inactive",
            )

        if session.revoked_at is not None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="SESSION_REVOKED",
                message="Session has been revoked",
            )

        if session.expires_at <= now:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="SESSION_EXPIRED",
                message="Session has expired",
            )

        # Detect refresh-token reuse. The outer refresh transaction must commit
        # the revocation before propagating the REFRESH_TOKEN_REUSE error.
        if token_record.consumed_at is not None:
            session.revoked_at = now

            await AuthSessionRepository.save(
                db=db,
                session=session,
            )

            logger.warning(
                "Refresh token reuse detected | code=%s | category=%s | "
                "session_id=%s | account_id=%s",
                REFRESH_TOKEN_REUSE,
                ErrorCategory.UNAUTHENTICATED.value,
                session.id,
                account.id,
            )

            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code=REFRESH_TOKEN_REUSE,
                message="Session is no longer valid",
            )

        # Validate refresh-token expiration
        if token_record.expires_at <= now:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="REFRESH_TOKEN_EXPIRED",
                message="Refresh token has expired",
            )

        # Recover original sliding session duration
        original_session_duration = (
            session.expires_at - session.last_activity_at
        )

        # Consume the existing refresh token
        token_record.consumed_at = now

        await AuthRefreshTokenRepository.save(
            db=db,
            token=token_record,
        )

        # Extend session expiration
        session.last_activity_at = now
        session.expires_at = now + original_session_duration

        await AuthSessionRepository.save(
            db=db,
            session=session,
        )

        # Generate replacement refresh token
        generated_refresh_token = generate_refresh_token()

        hashed_refresh_token = hash_refresh_token(
            generated_refresh_token
        )

        new_refresh_token = AuthRefreshToken(
            session_id=session.id,
            token_hash=hashed_refresh_token,
            expires_at=session.expires_at,
        )

        await AuthRefreshTokenRepository.create(
            db=db,
            token=new_refresh_token,
        )

        # Generate replacement access token
        claims = {
            "sub": str(account.id),
            "sid": str(session.id),
        }

        access_token_duration = timedelta(
            minutes=(
                60
                if settings.ENV == "dev"
                else settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        )

        remaining_session_duration = (
            session.expires_at - datetime.now(timezone.utc)
        )

        expires_in = int(
            min(
                access_token_duration,
                remaining_session_duration,
            ).total_seconds()
        )

        if expires_in <= 0:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="SESSION_EXPIRED",
                message="Session has expired",
            )

        access_token = create_access_token(
            claims,
            expires_delta=timedelta(seconds=expires_in),
        )

        # Construct token response
        token_pair_response = TokenPairResponse(
            access_token=access_token,
            refresh_token=generated_refresh_token,
            session_id=session.id,
            expires_in=expires_in,
            session_expires_at=session.expires_at,
        )

        logger.info(
            "Session renewal prepared | session_id=%s | account_id=%s",
            session.id,
            account.id,
        )

        return token_pair_response

    @staticmethod
    async def validate_session(
        db: AsyncSession,
        payload: SessionValidationRequest,
    ) -> SessionValidationResponse:
        session = await AuthSessionRepository.get_by_id(
            db=db,
            session_id=payload.session_id,
        )

        if session is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_SESSION",
                message="Session is invalid",
            )

        if session.account_id != payload.account_id:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_SESSION",
                message="Session is invalid",
            )

        if session.revoked_at is not None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="SESSION_REVOKED",
                message="Session has been revoked",
            )

        now = datetime.now(timezone.utc)

        if session.expires_at <= now:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="SESSION_EXPIRED",
                message="Session has expired",
            )

        account = await AuthAccountRepository.get_by_id(
            db=db,
            account_id=session.account_id,
        )

        if account is None:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="INVALID_SESSION",
                message="Session is invalid",
            )

        if account.status != AccountStatus.ACTIVE:
            raise ApplicationError(
                category=ErrorCategory.UNAUTHENTICATED,
                code="ACCOUNT_INACTIVE",
                message="Account is inactive",
            )

        validation_response = SessionValidationResponse(
            account_id=account.id,
            session_id=session.id,
            account_type=account.account_type,
            session_expires_at=session.expires_at,
        )

        return validation_response

    @staticmethod
    async def revoke_session(
        db: AsyncSession,
        payload: SessionRevokeRequest,
    ) -> None:
        session = await AuthSessionRepository.get_by_id(
            db=db,
            session_id=payload.session_id,
            lock=True,
        )

        if session is None:
            raise ApplicationError(
                category=ErrorCategory.NOT_FOUND,
                code="SESSION_NOT_FOUND",
                message="Session does not exist",
            )

        # Return immediately if the session has already been revoked.
        if session.revoked_at is not None:
            return None

        # Prepare the session for revocation.
        now = datetime.now(timezone.utc)

        session.revoked_at = now

        await AuthSessionRepository.save(
            db=db,
            session=session,
        )

        logger.info(
            "Session revocation prepared | session_id=%s | account_id=%s",
            session.id,
            session.account_id,
        )

        return None

    @staticmethod
    async def revoke_all_sessions(
        db: AsyncSession,
        payload: SessionRevokeAllRequest,
    ) -> SessionRevokeAllResponse:
        account = await AuthAccountRepository.get_by_id(
            db=db,
            account_id=payload.account_id,
            lock=True,
        )

        if account is None:
            raise ApplicationError(
                category=ErrorCategory.NOT_FOUND,
                code="ACCOUNT_NOT_FOUND",
                message="Account does not exist",
            )

        now = datetime.now(timezone.utc)

        revoked_count = await AuthSessionRepository.update_revoked_at_by_account_id(
            db=db,
            account_id=account.id,
            revoked_time=now,
        )

        logger.info(
            "Bulk session revocation prepared | account_id=%s | revoked_count=%s",
            account.id,
            revoked_count,
        )

        revoke_all_response = SessionRevokeAllResponse(
            account_id=account.id,
            revoked_count=revoked_count,
        )

        return revoke_all_response



    @staticmethod
    async def revoke_other_sessions(
        db : AsyncSession,
        payload : SessionRevokeOtherRequest
    ):

        account = await AuthAccountRepository.get_by_id(
            db = db ,
            account_id = payload.account_id,
            lock = True
        )


        if account is None:
            raise ApplicationError(
                category = ErrorCategory.NOT_FOUND,
                message = "Acount does not exist",
                code = "ACCOUNT_NOT_FOUND"
            )


        current_session = await AuthSessionRepository.get_by_id(
            db = db,
            session_id=payload.current_session_id
            lock = True
        )


        if current_session is None:
            raise ApplicationError(
                category = ErrorCategory.UNAUTHENTICATED,
                message = "Session is invalid",
                code = "INVALID_SESSION"
            )



        now = datetime.now(timezone.utc)

        if current_session.revoked_at is not None:
            raise ApplicationError(
                category = ErrorCategory.UNAUTHENTICATED,
                code = "SESSION_REVOKED",
                message = "Session has been revoked"
            )

        if current_session.expires_at <= now:
            raise ApplicationError(
                category = ErrorCategory.UNAUTHENTICATED,
                code = "SESSION_EXPIRED",
                message = "Session has expired"
            )

        




        