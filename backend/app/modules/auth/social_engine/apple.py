"""
Native Sign in with Apple ID-token verification for findspace.

AppleProvider verifies the token signature and required claims using
Apple's public signing keys from JWKSClient, then returns a normalized
VerifiedSocialIdentity. It never accesses accounts or issues sessions.
"""

from __future__ import annotations

import hmac

from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from app.modules.auth.enums import AuthIdentityProviders
from app.modules.auth.social_engine.base import BaseSocialProvider
from app.modules.auth.social_engine.contracts import (
    SocialVerificationRequest,
    VerifiedSocialIdentity,
)
from app.modules.auth.social_engine.exceptions import (
    ExpiredSocialTokenError,
    InvalidSocialTokenError,
)
from app.modules.auth.social_engine.jwks import JWKSClient


APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"
APPLE_ISSUER = "https://appleid.apple.com"
APPLE_ALLOWED_ALGORITHMS = ("RS256",)


class AppleProvider(BaseSocialProvider):
    """Verify Apple identity tokens obtained through native Apple Sign-In."""

    def __init__(
        self,
        jwks_client: JWKSClient,
        allowed_client_ids: list[str],
    ) -> None:
        """
        Configure trusted signing-key retrieval and accepted audiences.

        For native iOS sign-in, an allowed client ID is the registered
        application Bundle ID. A Services ID is used for applicable web flows.
        """
        if not allowed_client_ids or any(
            not isinstance(client_id, str) or not client_id.strip()
            for client_id in allowed_client_ids
        ):
            raise ValueError("At least one valid Apple Client ID is required")

        self._jwks_client = jwks_client
        self._allowed_client_ids = frozenset(
            client_id.strip() for client_id in allowed_client_ids
        )

    async def verify(
        self,
        request: SocialVerificationRequest,
    ) -> VerifiedSocialIdentity:
        """
        Verify Apple's signed identity token and normalize the user identity.

        expected_nonce, when provided, must come from a trusted authentication
        challenge. For native Apple flows that hash a raw nonce before sending
        it to Apple, pass the corresponding hash as expected_nonce.

        Raises:
            InvalidSocialTokenError: Invalid format, signature, claims or nonce.
            ExpiredSocialTokenError: Expired Apple identity token.
            SocialProviderUnavailableError: Propagated from JWKSClient if
                Apple's signing keys cannot be obtained.
        """
        token = request.id_token

        if not isinstance(token, str) or not token or len(token) > 16_384:
            raise InvalidSocialTokenError("Invalid Apple ID token")

        # The header is untrusted until the JWT signature is verified.
        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise InvalidSocialTokenError("Malformed Apple ID token") from exc

        if header.get("alg") not in APPLE_ALLOWED_ALGORITHMS:
            raise InvalidSocialTokenError("Unsupported Apple signing algorithm")

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidSocialTokenError("Missing Apple signing key identifier")

        # This JWKSClient must be initialized with APPLE_JWKS_URL by
        # the application's dependency-configuration layer.
        public_key = await self._jwks_client.get_key(kid)

        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=APPLE_ALLOWED_ALGORITHMS,
                issuer=APPLE_ISSUER,
                options={
                    "verify_aud": False,  # Validate against our allowlist below.
                    "verify_at_hash": False,  # No OAuth access token is provided.
                    "require_exp": True,
                    "require_iss": True,
                    "require_sub": True,
                    "require_iat": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise ExpiredSocialTokenError("Apple ID token has expired") from exc
        except JWTError as exc:
            raise InvalidSocialTokenError("Apple ID token verification failed") from exc

        # Native Apple ID tokens identify the app by its Bundle ID.
        # An Apple Services ID may be allowed for a separately configured
        # web flow. Never accept arbitrary audiences from the request.
        audience = claims.get("aud")
        if not isinstance(audience, str) or audience not in self._allowed_client_ids:
            raise InvalidSocialTokenError("Apple token was not issued for findspace")

        if request.expected_nonce is not None:
            expected_nonce = request.expected_nonce
            token_nonce = claims.get("nonce")

            if (
                not isinstance(expected_nonce, str)
                or not expected_nonce
                or not isinstance(token_nonce, str)
                or not hmac.compare_digest(
                    token_nonce.encode("utf-8"),
                    expected_nonce.encode("utf-8"),
                )
            ):
                raise InvalidSocialTokenError("Apple token nonce verification failed")

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise InvalidSocialTokenError("Invalid Apple account identifier")

        email = claims.get("email")
        if not isinstance(email, str) or not email.strip():
            email = None
        else:
            email = email.strip()

        email_verified_claim = claims.get("email_verified")
        email_verified = email is not None and (
            email_verified_claim is True or email_verified_claim == "true"
        )

        # Apple supplies the full name separately on first authorization;
        # it is not a claim in the verified identity token.
        return VerifiedSocialIdentity(
            provider=AuthIdentityProviders.APPLE,
            subject=subject,
            email_verified=email_verified,
            email=email,
            display_name=None,
            picture_url=None,
        )
