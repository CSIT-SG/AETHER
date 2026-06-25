# AETHER backend

Forwards RPC tool calls and manages agent specific memory. The transport is always [streamable http protocol, 2026-07-28](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http).

Run the server with `uv run scripts/run_headless.py`. Connect to the mcp server at `localhost:8000/mcp`.

You can spin up a test client as well:
- `export NODE_TLS_REJECT_UNAUTHORIZED=0` (to bypass ssl, set this env var)
- `bunx @modelcontextprotocol/inspector`
- Choose the streamable http transport. 