"""CLI entry point for the MCP Hello CIMD server."""

from __future__ import annotations

import logging
import sys

from mcp_hello_cimd.server import create_server

# Create server and expose Starlette sse_app for direct uvicorn usage
# e.g. `uvicorn mcp_hello_cimd.cli:app`
server = create_server()
app = server.sse_app()


def main() -> int:
    """Run the MCP server over stdio or SSE via uvicorn."""
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Run the MCP Hello CIMD server.")
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Run the server using SSE transport instead of stdio",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the SSE server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the SSE server to (default: 8000)",
    )
    parser.add_argument(
        "--loglevel",
        default="info",
        help="Log level for the server (default: info)",
    )

    args = parser.parse_args()

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        print(f"Invalid log level: {args.loglevel}", file=sys.stderr)
        return 1

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.sse:
        logger = logging.getLogger("mcp_hello_cimd.cli")
        logger.info(f"Starting MCP SSE server on {args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port, log_level=args.loglevel.lower())
    else:
        # Run over stdio
        server.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())