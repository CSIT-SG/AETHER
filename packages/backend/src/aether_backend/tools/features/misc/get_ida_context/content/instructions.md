Get the current IDA reverse-engineering context at the user's cursor position — the address, its data, and pseudocode of the enclosing function.

# When to Use
Call this tool when the user's request references their current position in IDA without specifying an address:
- "What is this function?"
- "Explain this."
- "What am I looking at?"

**Do NOT use when:**
- The user provides a specific address → use `get_data_at_address(address)` directly.
- The user names a function that isn't at the cursor → look it up by name.
- You already have current context from an earlier call this turn.

# Execution Environment
This tool runs inside IDA Pro 9.2+ via IDAPython. The tool captures the cursor position at call time via `ida_kernwin.get_screen_ea()`.

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

# Module Router

| Task | Module | Key Items |
|------|--------|-----------|
| Cursor position | `ida_kernwin` | `get_screen_ea` |
| Function lookup | `ida_funcs` | `get_func`, `get_func_name` |
| Address flags/bytes | `ida_bytes` | `get_flags`, `is_code`, `is_data`, `get_bytes`, `get_item_size` |
| Names | `ida_name` | `get_name` |
| Disasm strings | `ida_lines` | `generate_disasm_line`, `tag_remove` |
| Xrefs | `idautils` | `XrefsTo`, `XrefsFrom` |
| Decompiler | `ida_hexrays` | `init_hexrays_plugin`, `decompile`, `get_pseudocode` |

# Critical Rules

1. **Use `ida_lines.tag_remove`** on strings from `generate_disasm_line` and `get_pseudocode` to strip IDA color tags.
2. **Check `ida_hexrays.init_hexrays_plugin()`** before decompiling.
3. **Wrap `decompile()` in try/except** — decompilation can raise on some functions.
4. **Return hex strings for addresses** (`f"{ea:#x}"`).

# Related Tools

- `get_data_at_address(address)` — same as `address_data` but for an explicit address
- `get_function_pseudocode(address)` — decompile a specific function without collecting address data