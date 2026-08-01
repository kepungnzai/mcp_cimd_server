#!/usr/bin/env python
"""MCP Client script for testing the mcp-hello-cimd server."""

import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run_client():
    # Define server parameters to run the server over stdio
    # using the current virtualenv Python executable
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_hello_cimd.cli"],
        env=None,
    )

    print("Connecting to MCP server...")
    async with stdio_client(server_params) as (read_stream, write_stream):
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
            name = "Antigravity Tester"
            result = await session.call_tool("say_hello", arguments={"name": name})
            print(f"Arguments: {{'name': '{name}'}}")
            # Extract content from response (usually a list of text/image content)
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


if __name__ == "__main__":
    try:
        asyncio.run(run_client())
    except KeyboardInterrupt:
        print("\nClient terminated by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}", file=sys.stderr)
        sys.exit(1)
