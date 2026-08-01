"""MCP hello world server with a say_hello tool and server-side CIMD support."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_hello_cimd.cimd import (
    CIMDFetchError,
    CIMDProcessor,
    CIMDValidationError,
)

logger = logging.getLogger(__name__)

SERVER_NAME = "mcp-hello-cimd"
SERVER_VERSION = "0.1.0"


def create_server() -> FastMCP:
    """Create and configure the MCP server.

    This is the *server* side of MCP: it exposes tools for clients to call.
    It also implements the *server* side of CIMD: it consumes client metadata
    documents (client_id URLs), exactly as an authorization server would.
    """
    mcp = FastMCP(SERVER_NAME)
    cimd = CIMDProcessor()

    @mcp.tool()
    def say_hello(name: str = "world") -> str:
        """Say hello to someone.

        Args:
            name: The name to greet (defaults to 'world').

        Returns:
            A friendly greeting.
        """
        return f"Hello, {name}! Welcome to the MCP Hello CIMD server."

    @mcp.tool()
    def cimd_resolve(client_id: str) -> dict[str, Any]:
        """Resolve an OAuth client_id URL to its CIMD metadata document.

        Implements the *server-side* CIMD flow: validate the HTTPS URL,
        fetch the Client ID Metadata Document, validate the schema
        (client_id match, redirect_uris present, HTTPS redirect URIs),
        and cache the result with a TTL. SSRF protections are applied.

        Args:
            client_id: The client_id URL pointing to the CIMD document
                (e.g. https://client.example.com/oauth/metadata.json).

        Returns:
            The validated client metadata, or an error payload matching
            the CIMD error semantics (invalid_client /
            invalid_client_metadata) if resolution fails.
        """
        try:
            metadata = cimd.resolve(client_id)
            return {
                "client_id": client_id,
                "status": "ok",
                "metadata": metadata,
            }
        except CIMDFetchError as exc:
            return {
                "client_id": client_id,
                "error": "invalid_client",
                "error_description": str(exc),
            }
        except CIMDValidationError as exc:
            return {
                "client_id": client_id,
                "error": "invalid_client_metadata",
                "error_description": str(exc),
            }

    @mcp.tool()
    def cimd_cache_info() -> dict[str, Any]:
        """Inspect the CIMD metadata cache (admin/management tool).

        Returns:
            Cache contents with remaining TTL seconds per client_id.
        """
        return {
            "entries": cimd.cache_info(),
            "cached_client_ids": list(cimd.cache_info().keys()),
        }

    @mcp.tool()
    def cimd_clear_cache() -> dict[str, str]:
        """Force re-fetch of all cached CIMD metadata (admin tool).

        Returns:
            A confirmation message.
        """
        cimd.clear_cache()
        return {"status": "cache cleared"}

    return mcp