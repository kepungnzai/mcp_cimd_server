#!/usr/bin/env python
"""MCP Client script for testing the mcp-hello-cimd server remotely over SSE."""

import argparse
import asyncio
import sys
from mcp import ClientSession
from mcp.client.sse import sse_client


async def run_client(sse_url: str):
    print(f"Connecting to remote MCP server at {sse_url}...")
    try:
        async with sse_client(sse_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the session
                await session.initialize()
                print("Session initialized successfully.\n")

                # 1. List available tools
                print("=== Listing Tools ===")
                tools_response = await session.list_tools()
                for tool in tools_response.tools:
                    print(f"- {tool.name}: {tool.description}")
                print()

                # 2. Call say_hello tool
                print("=== Testing say_hello ===")
                name = "Remote Tester"
                result = await session.call_tool("say_hello", arguments={"name": name})
                print(f"Arguments: {{'name': '{name}'}}")
                for item in result.content:
                    if hasattr(item, "text"):
                        print(f"Response: {item.text}")
                    else:
                        print(f"Response: {item}")
                print()

                # 3. Call cimd_cache_info tool
                print("=== Testing cimd_cache_info ===")
                result = await session.call_tool("cimd_cache_info", arguments={})
                for item in result.content:
                    if hasattr(item, "text"):
                        print(f"Response: {item.text}")
                    else:
                        print(f"Response: {item}")
                print()
    except Exception as e:
        print(f"Failed to connect or communicate with the server: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the MCP SSE Remote Client.")
    parser.add_argument(
        "--url",
        default="http://localhost:8000/sse",
        help="The SSE endpoint URL of the remote MCP server (default: http://localhost:8000/sse)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(run_client(args.url))
    except KeyboardInterrupt:
        print("\nClient terminated by user.")
    except Exception as e:
        sys.exit(1)
