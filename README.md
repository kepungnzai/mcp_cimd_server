# MCP Hello CIMD

A **Model Context Protocol (MCP)** hello world server with a `say_hello` tool, that also implements the **server side** of **CIMD — Client ID Metadata Documents** (https://client.dev/servers).

> ⚠️ Important: this project is a **server**, not a client. It serves MCP tools to MCP clients and it *consumes* CIMD documents exactly as an OAuth **authorization server** would.

## What is CIMD?

CIMD (Client ID Metadata Documents) is a new OAuth approach that lets clients identify themselves using HTTPS URLs instead of preregistration. Instead of a client registry, an authorization server fetches the client's metadata just-in-time from the `client_id` URL.

This project implements the **server-side** CIMD processing flow from https://client.dev/servers:

1. **Receive OAuth request** — client sends `client_id` as an HTTPS URL
2. **Fetch CIMD document** — HTTPS GET to the `client_id` URL with `Accept: application/json`
3. **Validate schema & content** — parse JSON, verify required fields, check redirect URIs
4. **Enforce policies** — SSRF protections, size limits, TTL caching
5. **Proceed with OAuth flow** — return the validated metadata

## Features

### MCP (the hello world part)
- `say_hello(name)` — the classic hello world MCP tool

### CIMD (server-side implementation)
- `cimd_resolve(client_id)` — full CIMD server flow: validate URL → fetch → validate schema → cache
- `cimd_cache_info()` — admin tool to inspect the metadata cache
- `cimd_clear_cache()` — admin tool to force re-fetch of metadata

### Security (SSRF protections)
- **HTTPS only** — rejects non-HTTPS client_id URLs immediately
- **Private/loopback/link-local address blocking** — RFC 1918, 127.0.0.0/8, 169.254.0.0/16, IPv6 equivalents, and more
- **DNS rebinding protection** — resolves and validates DNS, pins IPs for requests
- **TLS validation** — validates certificates, modern TLS only
- **Size limits** — 5 KB max document size (per the CIMD spec)
- **Content-Type enforcement** — requires `application/json`
- **Redirect limits** — max 3 redirects, each hop re-validated
- **Cache with TTL** — 10 minute default TTL to balance freshness and performance

## Installation

```bash
pip install -e .
```

## Running the server

The server speaks MCP over stdio:

Or directly:

```bash
uvicorn mcp_hello_cimd.cli:app --port 8000
```

### Add to an MCP client (e.g. Claude Desktop / Cline)

Add to your MCP settings configuration (`mcpServers`):

```json
{
  "mcpServers": {
    "hello-cimd": {
      "command": "python",
      "args": ["-m", "mcp_hello_cimd.cli"]
    }
  }
}
```

## The CIMD flow in action

When an OAuth request arrives with a `client_id` like:

```
GET /authorize?client_id=https://client.example.com/.well-known/oauth-client-metadata.json&...
```

`cimd_resolve` performs the server-side flow:

```
1. Validate URL format                → must be https://
2. Check cache first                  → TTL 600s, returns if fresh
3. Fetch with SSRF protections        → 5KB limit, 10s timeout, 3 redirects max
4. Parse and validate JSON            → client_id must match URL, redirect_uris required
5. Cache and return metadata          → cached for 10 minutes
```

### Example metadata document a client would host

```json
{
  "client_id": "https://client.example.com/.well-known/oauth-client-metadata.json",
  "client_name": "Example OAuth Client",
  "client_uri": "https://client.example.com",
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "scope": "openid profile email"
}
```

### Error semantics

Per the CIMD server spec, failures produce clear OAuth-style errors:

| Condition | Error code |
|---|---|
| Metadata fetch failed (network, HTTP error) | `invalid_client` |
| Malformed JSON / missing required fields | `invalid_client_metadata` |
| SSRF violation (non-HTTPS, private IP, etc.) | `invalid_client_metadata` |

## Project layout

```
src/mcp_hello_cimd/
├── __init__.py
├── cli.py                # CLI entry point (stdio transport)
├── server.py             # MCP server: say_hello + CIMD tools
└── cimd/
    ├── __init__.py
    ├── ssrf.py           # SSRF protections (blocked ranges, DNS pinning)
    └── processor.py      # CIMD server flow: fetch → validate → cache
tests/
└── test_server.py        # Tests
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Resources

- [CIMD for Servers](https://client.dev/servers)
- [CIMD IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
- [Model Context Protocol](https://modelcontextprotocol.io)



