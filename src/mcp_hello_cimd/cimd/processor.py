"""Server-side CIMD processor.

Implements the authorization-server-side CIMD flow from https://client.dev/servers:
1. Receive OAuth request with client_id as HTTPS URL
2. Fetch CIMD document via HTTPS GET
3. Validate schema and content (client_id match, redirect_uris present, HTTPS redirects)
4. Enforce policies (SSRF protections, size limits, TTL caching)
"""

from __future__ import annotations

import http.client
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from mcp_hello_cimd.cimd.ssrf import SSRFValidationError, SSRFValidator

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_SIZE = 5120  # 5 KB limit as recommended by the CIMD spec
DEFAULT_TTL = 600  # 10 minutes


class CIMDError(Exception):
    """Base error for CIMD processing."""


class CIMDFetchError(CIMDError):
    """Raised when metadata cannot be fetched."""


class CIMDValidationError(CIMDError):
    """Raised when the metadata document is invalid."""


@dataclass
class CachedMetadata:
    """A cached metadata document with expiry."""

    metadata: dict[str, Any]
    expires_at: float
    cached_at: float = field(default_factory=time.time)


class CIMDProcessor:
    """Fetches, validates and caches CIMD metadata documents.

    This is the *server* side of CIMD: it consumes client metadata documents
    published by OAuth clients (identified by their HTTPS client_id URL).
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_size: int = DEFAULT_MAX_SIZE,
        ttl: float = DEFAULT_TTL,
        max_redirects: int = 3,
        validator: SSRFValidator | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_size = max_size
        self.ttl = ttl
        self.validator = validator or SSRFValidator(max_redirects=max_redirects)
        self._cache: dict[str, CachedMetadata] = {}

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def resolve(self, client_id: str) -> dict[str, Any]:
        """Resolve a client_id URL to validated client metadata.

        Implements the CIMD processing flow:
        1. Validate the client_id URL format (HTTPS only)
        2. Check the cache first
        3. Fetch with SSRF protections, timeouts and size limits
        4. Parse and validate the JSON document
        5. Cache and return the metadata

        Raises CIMDFetchError or CIMDValidationError with a descriptive message.
        """
        # 1. Validate URL format
        try:
            self.validator.validate_url(client_id)
        except SSRFValidationError as exc:
            raise CIMDValidationError(str(exc)) from exc

        # 2. Check cache first
        cached = self._cache.get(client_id)
        if cached and cached.expires_at > time.time():
            logger.debug("CIMD cache hit for %s", client_id)
            return dict(cached.metadata)

        # 3. Fetch with security protections
        try:
            body = self._fetch(client_id)
        except CIMDFetchError:
            logger.error("Failed to fetch CIMD for client_id=%s", client_id)
            raise

        # 4. Parse and validate JSON
        try:
            metadata = json.loads(body)
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in CIMD for client_id=%s: %s", client_id, exc)
            raise CIMDValidationError("Client metadata is not valid JSON") from exc

        if not isinstance(metadata, dict):
            raise CIMDValidationError("Client metadata must be a JSON object")

        self._validate_schema(metadata, client_id)

        # 5. Cache and return
        self._cache[client_id] = CachedMetadata(
            metadata=dict(metadata),
            expires_at=time.time() + self.ttl,
        )
        logger.debug("Cached CIMD for %s (TTL=%ss)", client_id, self.ttl)
        return metadata

    def clear_cache(self) -> None:
        """Force re-fetch of all metadata (admin/management tool)."""
        self._cache.clear()

    def cache_info(self) -> dict[str, float]:
        """Return cache inspection info (expiry timestamps per client_id)."""
        now = time.time()
        return {
            cid: entry.expires_at - now
            for cid, entry in self._cache.items()
            if entry.expires_at > now
        }

    # ------------------------------------------------------------------
    # Fetching
    # ------------------------------------------------------------------
    def _fetch(self, client_id: str) -> bytes:
        """Fetch the CIMD document with SSRF protections.

        - Pins the resolved IP to prevent DNS rebinding
        - Enforces size limits
        - Validates each redirect hop
        - Limits the number of redirects
        """
        redirects = 0
        req_url = client_id

        while True:
            # Validate URL format and resolve once with IP pinning
            # (DNS rebinding protection: connect to the pinned IP directly)
            self.validator.validate_url(req_url)
            _, pinned_ip = self.validator.lookup(req_url)

            parsed = urlparse(req_url)
            host = parsed.hostname
            port = parsed.port or 443
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            try:
                conn = http.client.HTTPSConnection(
                    pinned_ip,
                    port,
                    timeout=self.timeout,
                    context=self._ssl_context(),
                    server_hostname=host,  # SNI + cert validation against original host
                )
                conn.request(
                    "GET",
                    path,
                    headers={
                        "Host": f"{host}:{port}" if port != 443 else host,
                        "Accept": "application/json",
                        "User-Agent": "mcp-hello-cimd/0.1",
                    },
                )
                response = conn.getresponse()
            except (http.client.HTTPException, OSError) as exc:
                raise CIMDFetchError(
                    "Unable to fetch client metadata from specified URL"
                ) from exc

            try:
                # Enforce content-length limit when provided
                content_length = response.getheader("Content-Length")
                if content_length and int(content_length) > self.max_size:
                    raise CIMDFetchError("Client metadata document too large")

                content_type = response.getheader("Content-Type", "")
                if "application/json" not in content_type:
                    raise CIMDFetchError(
                        f"Invalid Content-Type: expected application/json, got {content_type!r}"
                    )

                body = response.read(self.max_size + 1)
                if len(body) > self.max_size:
                    raise CIMDFetchError("Client metadata document too large")

                # Handle redirects manually to re-validate each hop
                if response.status in (301, 302, 303, 307, 308):
                    redirects += 1
                    if redirects > self.validator.max_redirects:
                        raise CIMDFetchError("Too many redirects")
                    location = response.getheader("Location")
                    if not location:
                        raise CIMDFetchError("Redirect without Location header")
                    req_url = urljoin(req_url, location)
                    continue

                return body
            finally:
                response.close()
                conn.close()

    def _ssl_context(self):
        """Return a TLS context with modern TLS only and cert validation."""
        import ssl

        # Validate TLS certificates, only modern TLS versions
        return ssl.create_default_context()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def _validate_schema(self, metadata: dict[str, Any], expected_client_id: str) -> None:
        """Validate required fields and security rules."""
        # client_id must match the fetched URL
        doc_client_id = metadata.get("client_id")
        if not doc_client_id:
            raise CIMDValidationError("Client metadata missing required 'client_id' field")
        if doc_client_id != expected_client_id:
            raise CIMDValidationError(
                f"client_id mismatch: document says {doc_client_id!r}, "
                f"expected {expected_client_id!r}"
            )

        # redirect_uris is required
        redirect_uris = metadata.get("redirect_uris")
        if not redirect_uris:
            raise CIMDValidationError("Client metadata missing required 'redirect_uris' field")

        if not isinstance(redirect_uris, list):
            raise CIMDValidationError("'redirect_uris' must be an array")

        # Redirect URIs must use HTTPS (exact matches, no wildcards)
        for uri in redirect_uris:
            if not isinstance(uri, str):
                raise CIMDValidationError("Each redirect_uri must be a string")
            parsed_uri = urlparse(uri)
            if parsed_uri.scheme != "https":
                raise CIMDValidationError(
                    f"Redirect URIs must use HTTPS: {uri!r}"
                )
            if "*" in uri:
                raise CIMDValidationError(
                    f"Wildcards are not allowed in redirect_uris: {uri!r}"
                )

        # Validate client_uri and logo_uri if present
        for field_name in ("client_uri", "logo_uri", "tos_uri", "policy_uri"):
            uri = metadata.get(field_name)
            if uri is not None:
                if not isinstance(uri, str):
                    raise CIMDValidationError(f"{field_name!r} must be a string")
                if urlparse(uri).scheme not in ("https",):
                    raise CIMDValidationError(
                        f"{field_name!r} must use HTTPS: {uri!r}"
                    )