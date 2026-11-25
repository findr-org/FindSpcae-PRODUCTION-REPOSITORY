# ==========================#
# Google.py
# ==========================#

"""
Google ID-token verification provider for findspace.

Verifies Google-issued ID tokens using trusted public signing keys
retrieved through JWKSClient.

This provider is responsible for validating Google's token signatures,
issuer, audience, expiration, nonce, and identity claims.

It does not manage user accounts, database sessions, or issue findspace
authentication tokens.
"""

from __future__ import annotations

import hmac
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from app.modules.auth.models.identity import AuthIdentityProviders
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

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"


GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})

GOOGLE_ALLOWED_ALGORITHMS = "RS256"


class GoogleProvider(BaseSocialProvider):
    """Verify Google ID tokens and return normalized social identities"""

    def __init__(self, jwks_client: JWKSClient, allowed_clients_ids: list[str]):
        """
        Initialize the Goofle authentication provider

        Args:
            jwk_client:
                Reusable JWKSCLIENT configured with Google's
                trusted public signing-key endpoint.

            allowed_client_ids:
                Google OAuth Client IDs authorized to authenticate
                against findspace.
        Raises:
            ValueError:
                if the client ID configuration is empty or invalid
        """

        if not allowed_clients_ids or any(
            not isinstance(client_id, str) or not client_id.strip()
            for client_id in allowed_clients_ids
        ):
            raise ValueError("At least one valid Google Client ID is required")

        self._jwks_client = jwks_client

        self._allowed_client_ids = frozenset(
            client_id.strip() for client_id in allowed_clients_ids
        )


async def verify(
    self,
    request: SocialVerificationRequest,
) -> VerifiedSocialIdentity:
    """
    Verify a Google ID token and return its trusted identity.

    Validates the signing algorithm, RSA signature, issuer,
    audience, expiration, subject, and expected nonce.

    Raises:
        InvalidSocialTokenError:
            The token or its claims are invalid.

        ExpiredSocialTokenError:
            The token has expired.

        SocialProviderUnavailableError:
            Google's public signing keys could not be retrieved.
    """

    # BLOCK 1: Validate the incoming token and inspect its header.

    token = request.id_token

    if not isinstance(token, str) or not token or len(token) > 16_384:
        raise InvalidSocialTokenError("Invalid Google ID token")

    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise InvalidSocialTokenError("Malformed Google ID token") from exc

    if header.get("alg") not in GOOGLE_ALLOWED_ALGORITHMS:  # pyright: ignore[reportOperatorIssue]
        raise InvalidSocialTokenError("Unsupported Google signing algorithm")

    kid = header.get("kid")

    if not isinstance(kid, str) or not kid:
        raise InvalidSocialTokenError("Missing Google signing key identifier")

    # BLOCK 2: Retrieve Google's matching public signing key.

    public_key = await self._jwks_client.get_key(kid)

    # BLOCK 3: Cryptographically verify the token.

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=GOOGLE_ALLOWED_ALGORITHMS,
            issuer=GOOGLE_ISSUERS,
            options={
                "verify_aud": False,
                "verify_at_hash": False,
                "require_exp": True,
                "require_iss": True,
                "require_sub": True,
                "require_iat": True,
            },
        )

    except ExpiredSignatureError as exc:
        raise ExpiredSocialTokenError("Google ID token has expired") from exc

    except JWTError as exc:
        raise InvalidSocialTokenError("Google ID token verification failed") from exc

    # Validate audience against findspace's trusted client IDs.
    # python-jose accepts one expected audience string,
    # while findspace supports multiple registered client IDs.

    audience_claim = claims.get("aud")

    if isinstance(audience_claim, str):
        audiences = {audience_claim}

    elif (
        isinstance(audience_claim, list)
        and audience_claim
        and all(isinstance(item, str) for item in audience_claim)
    ):
        audiences = set(audience_claim)

    else:
        raise InvalidSocialTokenError("Invalid Google token audience")

    if not audiences.intersection(self._allowed_client_ids):
        raise InvalidSocialTokenError("Google token was not issued for findspace")

    # The authorized presenter must also be trusted when present.
    azp = claims.get("azp")

    if len(audiences) > 1 and azp is None:
        raise InvalidSocialTokenError("Missing authorized presenter")

    if azp is not None:
        if not isinstance(azp, str) or azp not in self._allowed_client_ids:
            raise InvalidSocialTokenError("Untrusted Google token presenter")

    # BLOCK 4: Validate the expected nonce when supplied.

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
            raise InvalidSocialTokenError("Google token nonce verification failed")

    # BLOCK 5: Validate and normalize the verified identity.

    subject = claims.get("sub")

    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise InvalidSocialTokenError("Invalid Google account identifier")

    email = claims.get("email")

    if not isinstance(email, str) or not email:
        email = None

    email_verified_claim = claims.get("email_verified")

    email_verified = email is not None and (
        email_verified_claim is True or email_verified_claim == "true"
    )

    display_name = claims.get("name")

    if not isinstance(display_name, str) or not display_name:
        display_name = None

    picture_url = claims.get("picture")

    if not isinstance(picture_url, str) or not picture_url:
        picture_url = None

    return VerifiedSocialIdentity(
        provider=AuthIdentityProviders.GOOGLE,
        subject=subject,
        email_verified=email_verified,
        email=email,
        display_name=display_name,
        picture_url=picture_url,
    )
