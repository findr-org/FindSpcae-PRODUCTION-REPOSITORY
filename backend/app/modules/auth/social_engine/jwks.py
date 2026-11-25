"""
Provider-agnostic JWKS retrieval and in-memory caching.

Retrieves public signing keys from a trusted JWKS endpoint and
resolves them by Key ID (kid).

Supports common asymmetric signing key formats:
- RSA: RS256/384/512, PS256/384/512
- EC: ES256/384/512
- OKP: EdDSA (Ed25519 and Ed448)

This module does not verify JWTs or determine which algorithms
a particular identity provider is allowed to use.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx

from app.modules.auth.social_engine.exceptions import (
    InvalidSocialTokenError,
    SocialProviderUnavailableError,
)


class JWKSClient:
    """Retrieve and cache public signing keys from a trusted JWKS endpoint."""

    _DEFAULT_TTL_SECONDS = 300
    _MAX_TTL_SECONDS = 86_400
    _REFRESH_COOLDOWN_SECONDS = 15
    _FAILURE_RETRY_SECONDS = 5
    _MAX_RESPONSE_BYTES = 65_536
    _MAX_KEYS = 32

    _RSA_ALGORITHMS = frozenset(
        {
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
        }
    )

    _EC_ALGORITHMS = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
    }

    _OKP_ALGORITHMS = {
        "Ed25519": frozenset({"EdDSA", "Ed25519"}),
        "Ed448": frozenset({"EdDSA", "Ed448"}),
    }

    def __init__(
        self,
        jwks_url: str,
        http_client: httpx.AsyncClient,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        """
        Initialize a client for one trusted JWKS endpoint.

        Args:
            jwks_url: Trusted HTTPS JWKS endpoint.
            http_client: Reusable asynchronous HTTP client.
            timeout_seconds: Maximum time for a JWKS fetch.
        """
        url = httpx.URL(jwks_url)

        if url.scheme != "https" or not url.host:
            raise ValueError("JWKS endpoint must use HTTPS")

        if timeout_seconds <= 0:
            raise ValueError("Timeout must be positive")

        self._jwks_url = str(url)
        self._http_client = http_client
        self._timeout_seconds = timeout_seconds

        # Public keys indexed by kid.
        self._keys: dict[str, dict] = {}

        # Monotonic timestamp when the cache expires.
        self._expires_at = 0.0

        # None means no successful forced refresh yet.
        self._last_forced_refresh: float | None = None

        # Prevent immediate repeated retries after fetch failures.
        self._retry_after = 0.0

        # One refresh at a time per client instance.
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> dict:
        """
        Return the public JWK matching the provided kid.

        Fresh cache hits require no network request.

        Expired caches are refreshed. Unknown kids can trigger
        an early refresh, subject to a cooldown.

        Raises:
            InvalidSocialTokenError:
                Invalid or unknown signing key identifier.

            SocialProviderUnavailableError:
                The required public keys cannot be retrieved.
        """
        if not isinstance(kid, str) or not 0 < len(kid) <= 256:
            raise InvalidSocialTokenError("Invalid signing key identifier")

        # Fast path: serve an existing fresh key.
        if self._cache_is_fresh():
            key = self._keys.get(kid)

            if key is not None:
                return dict(key)

        async with self._lock:
            # Another coroutine may have updated the cache
            # while this request was waiting for the lock.
            if self._cache_is_fresh():
                key = self._keys.get(kid)

                if key is not None:
                    return dict(key)

            now = time.monotonic()

            # A previous fetch failed recently.
            # Do not repeatedly contact an unavailable provider.
            if now < self._retry_after:
                raise SocialProviderUnavailableError(
                    "Signing keys temporarily unavailable"
                )

            if self._cache_is_fresh():
                # The cache is valid, but kid is unknown.
                # Only permit periodic early refreshes.
                if self._last_forced_refresh is not None:
                    elapsed = now - self._last_forced_refresh

                    if elapsed < self._REFRESH_COOLDOWN_SECONDS:
                        raise InvalidSocialTokenError("Unknown signing key")

                await self._refresh_cache()

                # Record only successful forced refreshes.
                self._last_forced_refresh = time.monotonic()

            else:
                # Expired or empty cache: normal refresh.
                await self._refresh_cache()

            key = self._keys.get(kid)

            if key is None:
                raise InvalidSocialTokenError("Unknown signing key")

            return dict(key)

    def _cache_is_fresh(self) -> bool:
        """Return whether the cache contains unexpired keys."""
        return bool(self._keys) and time.monotonic() < self._expires_at

    async def _refresh_cache(self) -> None:
        """
        Download, validate, and replace the cached JWKS.

        Supports public RSA, EC, and OKP signing keys.

        The existing cache is replaced only after successful
        retrieval and validation of the entire response.
        """
        try:
            # Limit the total time spent fetching the response.
            async with asyncio.timeout(self._timeout_seconds):
                async with self._http_client.stream(
                    "GET",
                    self._jwks_url,
                    timeout=self._timeout_seconds,
                    follow_redirects=False,
                ) as response:
                    response.raise_for_status()

                    body = bytearray()

                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > self._MAX_RESPONSE_BYTES:
                            raise SocialProviderUnavailableError(
                                "JWKS response exceeds size limit"
                            )

                        body.extend(chunk)

                    payload = json.loads(body)
                    headers = response.headers

            if not isinstance(payload, dict):
                raise SocialProviderUnavailableError("Invalid JWKS document")

            published_keys = payload.get("keys")

            if (
                not isinstance(published_keys, list)
                or not 0 < len(published_keys) <= self._MAX_KEYS
            ):
                raise SocialProviderUnavailableError("Invalid JWKS key collection")

            new_keys: dict[str, dict] = {}

            for key in published_keys:
                if not isinstance(key, dict):
                    raise SocialProviderUnavailableError("Invalid JWK entry")

                kty = key.get("kty")

                # Only public asymmetric signing keys.
                if kty not in {"RSA", "EC", "OKP"}:
                    continue

                # Ignore keys not intended for signatures.
                if key.get("use") not in (None, "sig"):
                    continue

                key_ops = key.get("key_ops")

                if key_ops is not None:
                    if (
                        not isinstance(key_ops, list)
                        or "verify" not in key_ops
                        or "sign" in key_ops
                    ):
                        continue

                # Determine required fields and supported
                # algorithms for this public-key type.
                if kty == "RSA":
                    required_fields = ("n", "e")
                    allowed_algorithms = self._RSA_ALGORITHMS

                elif kty == "EC":
                    curve = key.get("crv")

                    if curve not in self._EC_ALGORITHMS:
                        continue

                    required_fields = ("crv", "x", "y")
                    allowed_algorithms = {self._EC_ALGORITHMS[curve]}

                else:  # OKP
                    curve = key.get("crv")

                    if curve not in self._OKP_ALGORITHMS:
                        continue

                    required_fields = ("crv", "x")
                    allowed_algorithms = self._OKP_ALGORITHMS[curve]

                # If the provider declares an algorithm,
                # it must match the key's supported family.
                algorithm = key.get("alg")

                if algorithm is not None and algorithm not in allowed_algorithms:
                    continue

                kid = key.get("kid")

                if not isinstance(kid, str) or not 0 < len(kid) <= 256:
                    raise SocialProviderUnavailableError("Invalid JWK key identifier")

                # Validate required public-key field presence.
                for field in required_fields:
                    value = key.get(field)

                    if not isinstance(value, str) or not value:
                        raise SocialProviderUnavailableError(
                            "Invalid public-key parameters"
                        )

                # Reject entries containing private or
                # symmetric key material.
                private_fields = {
                    "d",
                    "p",
                    "q",
                    "dp",
                    "dq",
                    "qi",
                    "oth",
                    "k",
                }

                if private_fields.intersection(key):
                    raise SocialProviderUnavailableError(
                        "JWKS contains private key material"
                    )

                if kid in new_keys:
                    raise SocialProviderUnavailableError(
                        "Duplicate JWKS key identifier"
                    )

                # Retain only public parameters and relevant
                # verification metadata.
                public_key = {
                    "kty": kty,
                    "kid": kid,
                }

                for field in required_fields:
                    public_key[field] = key[field]

                if algorithm is not None:
                    public_key["alg"] = algorithm

                if key.get("use") is not None:
                    public_key["use"] = key["use"]

                new_keys[kid] = public_key

            if not new_keys:
                raise SocialProviderUnavailableError("No supported public signing keys")

            ttl = self._get_cache_ttl(headers)

        except (
            httpx.HTTPError,
            TimeoutError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            self._retry_after = time.monotonic() + self._FAILURE_RETRY_SECONDS

            raise SocialProviderUnavailableError(
                "Unable to retrieve valid provider signing keys"
            ) from exc

        except SocialProviderUnavailableError:
            self._retry_after = time.monotonic() + self._FAILURE_RETRY_SECONDS

            raise

        # Only successful, fully validated responses
        # can replace the existing cache.
        self._keys = new_keys
        self._expires_at = time.monotonic() + ttl

        # Clear the failure backoff after success.
        self._retry_after = 0.0

    def _get_cache_ttl(self, headers: httpx.Headers) -> int:
        """
        Determine cache freshness from HTTP Cache-Control.

        Handles max-age, no-cache, no-store, and Age.
        Falls back to a short application-defined TTL.
        """
        cache_control = headers.get("cache-control", "")

        directives = [
            directive.strip().lower() for directive in cache_control.split(",")
        ]

        if "no-store" in directives or "no-cache" in directives:
            return 0

        max_age = None

        for directive in directives:
            if directive.startswith("max-age="):
                value = directive.partition("=")[2].strip('"')

                if value.isdecimal():
                    max_age = int(value)

                break

        if max_age is None:
            max_age = self._DEFAULT_TTL_SECONDS

        age_header = headers.get("age", "0")

        response_age = int(age_header) if age_header.isdecimal() else 0

        remaining_ttl = max(
            0,
            max_age - response_age,
        )

        return min(
            remaining_ttl,
            self._MAX_TTL_SECONDS,
        )
