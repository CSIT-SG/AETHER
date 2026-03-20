import json
from typing import Any, Dict
from urllib.parse import urlparse

import ida_kernwin
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from ainalyse.annotator import parse_llm_annotations
from ainalyse.custom_set_cmt import scmt  # Import custom set_comment implementation
from ainalyse.utils import refresh_functions


def _extract_tool_text(result) -> str | None:
    """Extract plain text payload from an MCP tool call result."""
    try:
        if result and getattr(result, "content", None):
            first = result.content[0]
            if first and hasattr(first, "text"):
                return first.text
    except Exception:
        pass
    return None


async def _resolve_function_address(session: ClientSession, function_name: str) -> str | None:
    """Resolve function address by name through MCP."""
    if not function_name:
        return None
    try:
        result = await session.call_tool("get_function_by_name", {"name": function_name})
        text = _extract_tool_text(result)
        if not text:
            return None
        data = json.loads(text)
        address = data.get("address")
        return address if isinstance(address, str) and address.strip() else None
    except Exception:
        return None


async def undo_analysis_annotations(analysis_entry: Dict[str, Any], config: dict) -> bool:
    """Undo annotations from a specific analysis entry using MCP."""
    server_url = config["MCP_SERVER_URL"]
    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] Error: Invalid MCP_SERVER_URL for undo operation")
        return False
    
    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] Connected to MCP server for undo operation.")
                
                # Path 1, annotate single undo
                structured = analysis_entry.get("commands")
                if structured:
                    starting_function_addr = analysis_entry.get("starting_function_addr")
                    if not starting_function_addr:
                        starting_function_addr = await _resolve_function_address(session, analysis_entry.get("starting_function", ""))

                    success_count = 0

                    # 1. Undo Comments
                    for cmd in structured.get("comments", []):
                        if not cmd.get("address"):
                            continue

                        def _clear_comment_sync():
                            try:
                                scmt(cmd["address"], "")
                                return True
                            except Exception:
                                return False

                        if ida_kernwin.execute_sync(_clear_comment_sync, ida_kernwin.MFF_WRITE):
                            success_count += 1
                    
                    # 2. Undo Variable Renames (Swap new_name and old_name)
                    for var in structured.get("local_variables", []):
                        if not starting_function_addr:
                            continue
                        old_name = var.get("new_name")
                        new_name = var.get("old_name")
                        if not old_name or not new_name:
                            continue
                        await session.call_tool("rename_local_variable", {
                            "function_address": starting_function_addr,
                            "old_name": old_name,
                            "new_name": new_name
                        })
                        success_count += 1
                        
                    # 3. Undo Function Renames
                    for fn in structured.get("function_renames", []):
                        function_address = fn.get("address")
                        if not function_address:
                            function_address = await _resolve_function_address(session, fn.get("old_name", ""))
                        if not function_address:
                            continue
                        await session.call_tool("rename_function", {
                            "function_address": function_address,
                            "new_name": ""
                        })
                        success_count += 1

                    refresh_functions(fallback_func_addr=starting_function_addr, log_prefix="[AETHER] [Undo]")
                    print(f"[AETHER] [Undo] Successfully undid {success_count} structured annotation change(s).")
                    return success_count > 0

                # Path 2, annotator tree undo
                annotator_output = analysis_entry.get("annotator_output", "")
                if not annotator_output:
                    print("[AETHER] No annotator output found in analysis entry.")
                    return True
                
                # Parse the annotator output to extract applied commands
                commands = await parse_llm_annotations(annotator_output, {}, False, session)
                
                success_count = 0
                processed_commands = set()  # Track processed commands to avoid duplicates
                
                for command in commands:
                    # Create a unique identifier for this command to avoid duplicates
                    command_id = f"{command['type']}_{command.get('address', '')}_{command.get('function_address', '')}_{command.get('old_name', '')}_{command.get('new_name', '')}"
                    if command_id in processed_commands:
                        continue
                    processed_commands.add(command_id)
                    
                    try:
                        if command["type"] == "set_comment":
                            # Use custom set_comment implementation to remove comment
                            def _clear_comment_sync():
                                try:
                                    scmt(command["address"], "")
                                    return True
                                except Exception as e:
                                    print(f"[AETHER] [Undo] Error clearing comment at {command['address']}: {e}")
                                    return False
                            
                            if ida_kernwin.execute_sync(_clear_comment_sync, ida_kernwin.MFF_WRITE):
                                print(f"[AETHER] [Undo] Removed comment at {command['address']}")
                                success_count += 1
                            # Remove sleep delay
                            
                        elif command["type"] == "rename_function":
                            # Get current function info to determine proper restoration name
                            func_info = await session.call_tool("get_function_by_address", {
                                "address": command["function_address"]
                            })
                            if func_info.content and func_info.content[0]:
                                func_data = json.loads(func_info.content[0].text)
                                current_name = func_data.get("name", "")
                                
                                # Only restore if current name matches what we expect to have renamed
                                if current_name == command["new_name"]:
                                    # Generate proper original name based on address
                                    # addr_hex = command["function_address"].replace('0x', '').upper()
                                    
                                    await session.call_tool("rename_function", {
                                        "function_address": command["function_address"],
                                        "new_name": ""
                                    })
                                    print(f"[AETHER] [Undo] Restored function name from {command['new_name']} to IDA default")
                                    success_count += 1
                                else:
                                    print(f"[AETHER] [Undo] Skipping function rename - current name '{current_name}' doesn't match expected '{command['new_name']}'")
                            # Remove sleep delay
                                
                        elif command["type"] == "rename_local_variable":
                            # Get current variable info to verify before undoing
                            try:
                                # Restore original variable name (swap old/new for undo)
                                await session.call_tool("rename_local_variable", {
                                    "function_address": command["function_address"],
                                    "old_name": command["new_name"],  # Current name (what was renamed to)
                                    "new_name": command["old_name"]   # Original name (what to restore)
                                })
                                print(f"[AETHER] [Undo] Restored variable from {command['new_name']} to {command['old_name']} in func {command['function_address']}")
                                success_count += 1
                            except Exception as var_error:
                                print(f"[AETHER] [Undo] Failed to restore variable {command['new_name']} -> {command['old_name']}: {var_error}")
                            # Remove sleep delay
                            
                    except Exception as e:
                        print(f"[AETHER] [Undo] Failed to undo command {command}: {e}")
                        # Remove sleep delay

                    refresh_functions(fallback_func_addr=analysis_entry.get("starting_function_addr"), log_prefix="[AETHER] [Undo]")
                print(f"[AETHER] [Undo] Successfully undid {success_count}/{len(processed_commands)} unique annotations.")
                return success_count > 0
                
    except Exception as e:
        print(f"[AETHER] [Undo] Error during undo operation: {e}")
        return False
