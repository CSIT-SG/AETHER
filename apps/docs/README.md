# AETHER Docs

Nextra-themed docs for aether.

Includes autogeneration of docstrings, as well as internal and public guides.

## Development

Requires `bun`. 

1. `bun i` (`export NODE_TLS_REJECT_UNAUTHORIZED=0` if ssl errors)
2. `bun run dev`

If you want to install a mcp server for these docs, paste this in your config:

```
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