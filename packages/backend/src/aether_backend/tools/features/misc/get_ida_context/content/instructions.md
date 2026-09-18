Get the current IDA reverse-engineering context at given address — the address, its data, and pseudocode of the enclosing function.

# When to Use
Call this tool when the user's request references an address but doesn't give enough context:
- "What is this function at 0x14676767?"
- "Explain the function at 0x14676767."

**Do NOT use when:**
- The user provides a specific address → use `get_data_at_address(address)` directly.
- You already have current context from an earlier call this turn.

# Execution Environment
This tool runs inside IDA Pro 9.2+ via IDAPython.

# Return Structure

Returns a single object containing two sub-objects:

## `address_data` (always present)

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Hex address at the cursor |
| `name` | string \| null | Symbol name if defined |
| `function` | object \| null | Enclosing function info if inside one |
| `item_size` | int | Size of the item at this address in bytes |
| `raw_bytes` | string | Hex-encoded raw bytes |
| `is_code` | bool | True if this address contains code |
| `is_data` | bool | True if this address contains data |
| `disassembly` | string \| null | Cleaned disassembly line |
| `xrefs_to` | list | Cross-refs pointing to this address |
| `xrefs_from` | list | Cross-refs originating from this address |

## `function_pseudocode` (null if not inside a function)

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Function name |
| `start_address` | string | Function start in hex |
| `pseudocode` | string | Hex-Rays decompiled C code |
