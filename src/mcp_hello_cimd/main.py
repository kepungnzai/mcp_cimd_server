"""CLI entry point for the MCP Hello CIMD server."""

from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import logging
import sys

from mcp_hello_cimd.server import create_server

server = create_server()

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with AsyncExitStack() as stack:
        await stack.enter_async_context(server.session_manager.run())
        yield

app = FastAPI(lifespan=lifespan)

@app.get("/health")
async def health():
    return JSONResponse({"status": "healthy"})

app.mount("/", server.streamable_http_app())
