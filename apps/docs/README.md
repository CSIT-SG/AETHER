# AETHER Docs

Nextra-themed docs for aether.

Includes autogeneration of docstrings, as well as internal and public guides.

## Development

Requires `bun`. If you don't have it installed:

- Linux / macOS:
  ```sh
  curl -fsSL https://bun.sh/install | bash
  ```
- Windows (PowerShell):
  ```powershell
  powershell -c "irm bun.sh/install.ps1 | iex"
  ```

1. `bun i` (if you hit SSL errors, disable TLS verification first — see below)
2. `bun run dev`

To disable TLS verification:

- Linux / macOS:
  ```sh
  export NODE_TLS_REJECT_UNAUTHORIZED=0
  ```
- Windows (PowerShell):
  ```powershell
  $env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
  ```

If you want to install an mcp server for these docs, paste this in your config:

- Linux / macOS:
  ```jsonc
  // claude_desktop_config.json
  {
    "mcpServers": {
      "aether-docs": {
        "command": "NODE_TLS_REJECT_UNAUTHORIZED=0 bunx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "apps/docs/src/content"]
      }
    }
  }
  ```
- Windows: set `NODE_TLS_REJECT_UNAUTHORIZED=0` in your environment first (see above), then use `bunx` as the command:
  ```jsonc
  // claude_desktop_config.json
  {
    "mcpServers": {
      "aether-docs": {
        "command": "bunx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "apps/docs/src/content"]
      }
    }
  }
  ```

## Running

We have a docker image built by github actions on every push to master. Just download and `docker load` that. Expose port `3000`.

Or, run `bun run build` and then `bun run start`.

Or, `docker build -f apps/docs/Dockerfile -t aether-docs .` from the root.

> **Note:** search (Pagefind) only works in a production build. `bun run dev` has no search index — run `bun run build` then `bun run start` to try it locally. The `build` step generates the index and stages it into the standalone server that `start` serves.
