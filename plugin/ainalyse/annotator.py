import json
import os
import re
import traceback
import textwrap
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import ida_kernwin
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from ainalyse import finalize_prompt
from ainalyse.custom_set_cmt import scmt  # Import custom set_comment implementation
from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from ainalyse.utils import check_and_add_intranet_headers

# --- File Paths (relative to this file's location in 'ainalyse' directory) ---
PROMPT_ANNOTATOR = os.path.join(os.path.dirname(__file__), "prompts/annotator-prompt.txt")
PROMPT_ANNOTATOR_FAST = os.path.join(os.path.dirname(__file__), "prompts/annotator-prompt-fast.txt")

# Use lazy initialization to avoid circular import
CTX_FILE_PATH = None
VERBOSE_LOG_PATH = None

def _init_paths():
    """Initialize file paths lazily to avoid circular imports"""
    global CTX_FILE_PATH, VERBOSE_LOG_PATH
    if CTX_FILE_PATH is None:
        from ainalyse import get_data_directory
        data_dir = get_data_directory()
        CTX_FILE_PATH = os.path.join(data_dir, "ctx.txt")
        VERBOSE_LOG_PATH = os.path.join(data_dir, "verbose.txt")

# --- Annotator Logic ---

# Helper function to get text content from MCP tool (similar to plugin.py)
async def _mcp_get_tool_text_content(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> Optional[str]:
    try:
        res = await session.call_tool(tool_name, params if params else {})
        if res.content and res.content[0] and hasattr(res.content[0], 'text'):
            return res.content[0].text
    except Exception as e:
        print(f"[AETHER] [Annotator] Error calling MCP tool {tool_name} for text: {e}")
    return None

def call_openai_llm_annotator(system_prompt: str, user_prompt: str, api_key: str, model: str, base_url: str, max_tokens: int = 8192, extra_body: dict = None, custom_ca_cert_path: str = "", client_cert_path: str = "", client_key_path: str = "") -> str:
    try:
        feature = "annotation"
        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path,feature)
        
        # Prepare request parameters
        request_params = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.7
        }
        
        # Add extra_body if provided
        if extra_body:
            request_params["extra_body"] = extra_body
        
        # Check for intranet.txt and add headers if needed
        check_and_add_intranet_headers(request_params)
        
        response = client.chat.completions.create(**request_params)
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[AETHER] Error calling OpenAI API (annotator): {e}")
        return ""

async def parse_llm_annotations(
    response_text: str, 
    name_line_to_addr: Dict[str, Dict[str, str]],  # This parameter is now unused but kept for compatibility
    rename_filter_enabled: bool,
    session: Optional[ClientSession],
    fast_mode: bool = False
) -> List[Dict[str, Any]]:
    parsed_commands = []
    
    # Parse set_comment blocks using regex to handle both formats properly
    # Match ```set_comment or ```set_comment(function_name) followed by content until ```
    set_comment_pattern = re.compile(r'```set_comment(?:\([^)]*\))?\s*\n(.*?)(?=\n```|$)', re.DOTALL | re.IGNORECASE)
    for match in set_comment_pattern.finditer(response_text):
        comment_lines_str = match.group(1).strip()
        
        for line_entry in comment_lines_str.split('\n'):
            line_entry = line_entry.strip()
            if not line_entry:
                continue
            
            if fast_mode:
                # Fast mode: address|commentText (no reason field)
                parts = line_entry.split('|', 1)
                if len(parts) >= 2:
                    address, comment_text = parts[0].strip(), parts[1].strip()
                    if address and comment_text:
                        parsed_commands.append({
                            "type": "set_comment",
                            "address": address,
                            "comment": comment_text
                        })
                        print(f"[AETHER] [Annotator] Parsed set_comment: {address} -> {comment_text}")
                else:
                    print(f"[AETHER] [Annotator] Malformed set_comment line: '{line_entry}'. Skipping.")
            else:
                # Normal mode: address|commentText|reason (reason is optional and not used by parser)
                parts = line_entry.split('|', 2)
                if len(parts) >= 2:
                    address, comment_text = parts[0].strip(), parts[1].strip()
                    if address and comment_text:
                        parsed_commands.append({
                            "type": "set_comment",
                            "address": address,
                            "comment": comment_text
                        })
                        print(f"[AETHER] [Annotator] Parsed set_comment: {address} -> {comment_text}")
                else:
                    print(f"[AETHER] [Annotator] Malformed set_comment line: '{line_entry}'. Skipping.")

    # Parse rename_local_variable blocks
    IDA_DUMMY_VAR_RE = re.compile(
    # Generic IDA Decompiler Prefixes
    r'^(v|a|s|arg|var_|low|high|byte_|word_|dword_|qword_|__)\d*$|'
    # Result and Stack Metadata
    r'^result$|^savedregs$|^anonymous_\d+$|'
    # x86/x64 General Purpose Registers (RAX, EAX, AX, AL, AH, R8, R8D, etc.)
    r'^_?(_.*_)?([RE]?[ABCD]X|[ABCD][LH]|R[89]|R1[0-5])[DBW]?$|'
    # x86/x64 Index/Pointer Registers (RSI, EDI, RBP, RSP, etc.)
    r'^_?(_.*_)?([RE]?[SD]I|[RE]?[BS]P|[RE]?IP)$|'
    # ARM/Other Architecture Registers (R0-R15, X0-X31, W0-W31)
    r'^_?(_.*_)?([RXW]\d{1,2}|LR|PC|SP|FP|SL|SB)$|'
    # Floating Point / SIMD (XMM0-15, YMM0-15, ZMM0-31, ST0-7, Q0-31, D0-31)
    r'^_?(_.*_)?([XYZ]MM\d{1,5}|ST\d|Q\d{1,2}|D\d{1,2})$|'
    # Common Generic Short-hands
    r'^(s|n|i|j|k|fd|pid|name|flags|src|dest|buf|ptr|len|res|ret|status|val)$',
    re.IGNORECASE
    )
    rename_var_pattern = re.compile(r'```rename_local_variable\s*\n(.*?)(?=\n```|$)', re.DOTALL | re.IGNORECASE)
    for match in rename_var_pattern.finditer(response_text):
        var_lines_str = match.group(1).strip()
        
        for line_entry in var_lines_str.split('\n'):
            line_entry = line_entry.strip()
            if not line_entry:
                continue
                
            if fast_mode:
                # Fast mode: function_address|old_name|new_name (no reason field)
                parts = [p.strip() for p in line_entry.split('|')]
                if len(parts) >= 3:
                    func_addr, old_name, new_name = parts[0], parts[1], parts[2]
                else:
                    print(f"[AETHER] [Annotator] Malformed rename_local_variable line: '{line_entry}'. Skipping.")
                    continue
            else:
                # Normal mode: function_address|old_name|new_name|reason
                parts = [p.strip() for p in line_entry.split('|')] 
                if len(parts) >= 3:
                    func_addr, old_name, new_name = parts[0], parts[1], parts[2]
                else:
                    print(f"[AETHER] [Annotator] Malformed rename_local_variable line: '{line_entry}'. Skipping.")
                    continue

            if rename_filter_enabled:
                if not IDA_DUMMY_VAR_RE.match(old_name):
                    print(f"[AETHER] [Annotator] Skipping rename of variable '{old_name}' to '{new_name}' in func {func_addr} due to filter (not a default pattern like v1 or a1).")
                    continue
            
            if func_addr and old_name and new_name:
                parsed_commands.append({
                    "type": "rename_local_variable",
                    "function_address": func_addr,
                    "old_name": old_name,
                    "new_name": new_name
                })
            else:
                print(f"[AETHER] [Annotator] Malformed rename_local_variable line (empty mandatory part): '{line_entry}'. Skipping.")

    # Parse rename_function blocks
    IDA_DUMMY_FUNC_RE = re.compile(r'^(aire_|sub|nullsub|loc|unk|off|asc|byte|word|dword|qword|j|__imp|__wrapper)_[0-9a-fA-F]+$', re.IGNORECASE)
    rename_func_pattern = re.compile(r'```rename_function\s*\n(.*?)(?=\n```|$)', re.DOTALL | re.IGNORECASE)
    for match in rename_func_pattern.finditer(response_text):
        func_lines_str = match.group(1).strip()
        
        for line_entry in func_lines_str.split('\n'):
            line_entry = line_entry.strip()
            if not line_entry:
                continue
                
            if fast_mode:
                # Fast mode: function_address|new_name (no reason field)
                parts = [p.strip() for p in line_entry.split('|')]
                if len(parts) >= 2:
                    func_addr_str, new_name = parts[0], parts[1]
                else:
                    print(f"[AETHER] [Annotator] Malformed rename_function line: '{line_entry}'. Skipping.")
                    continue
            else:
                # Normal mode: function_address|new_name|reason
                parts = [p.strip() for p in line_entry.split('|')]
                if len(parts) >= 2:
                    func_addr_str, new_name = parts[0], parts[1]
                else:
                    print(f"[AETHER] [Annotator] Malformed rename_function line: '{line_entry}'. Skipping.")
                    continue

            if rename_filter_enabled and session:
                # Use get_function_by_address and parse JSON
                func_info_json = await _mcp_get_tool_text_content(session, "get_function_by_address", {"address": func_addr_str})
                current_func_name = None
                if func_info_json:
                    try:
                        func_info = json.loads(func_info_json)
                        current_func_name = func_info.get("name", None)
                    except Exception as e:
                        print(f"[AETHER] [Annotator] Failed to parse MCP get_function_by_address response: {e}")
                if not (current_func_name and IDA_DUMMY_FUNC_RE.match(current_func_name)):
                    print(f"[AETHER] [Annotator] Skipping rename of function '{current_func_name or func_addr_str}' to '{new_name}' due to filter (current name does not start with 'sub_').")
                    continue

            if func_addr_str and new_name:
                parsed_commands.append({
                    "type": "rename_function",
                    "function_address": func_addr_str,
                    "new_name": new_name
                })
            else:
                print(f"[AETHER] [Annotator] Malformed rename_function line (empty mandatory part): '{line_entry}'. Skipping.")
    
    return parsed_commands

async def mcp_execute_tool(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> bool:
    try:
        # Handle set_comment with custom implementation instead of MCP
        if tool_name == "set_comment":
            address = params.get("address", "")
            comment = params.get("comment", "")
            
            # Execute custom set_comment on main thread
            def _set_comment_sync():
                try:
                    scmt(address, comment)
                    return True
                except Exception as e:
                    print(f"[AETHER] Error setting comment at {address}: {e}")
                    return False
            
            return ida_kernwin.execute_sync(_set_comment_sync, ida_kernwin.MFF_WRITE)
        else:
            # Use MCP for other tools
            await session.call_tool(tool_name, params if params else {})
            return True
    except Exception as e:
        print(f"[AETHER] Error calling tool {tool_name} with params {params}: {e}")
        return False

def extract_root_function_name(ctx_content: str) -> Optional[str]:
    match = re.search(r"FINAL CALL TREE:\n(.*?)\s*\[", ctx_content)
    if match:
        return match.group(1).strip()
    return None

async def run_annotator_agent(config: dict):
    _init_paths()  # Initialize file paths lazily to avoid circular imports
    
    server_url = config["MCP_SERVER_URL"]
    api_key = config["OPENAI_API_KEY"]
    model = config["ANNOTATOR_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    rename_filter_enabled = config.get("RENAME_FILTER_ENABLED", True)
    fast_mode = config.get("fast_mode", False)
    custom_user_prompt = config.get("custom_user_prompt", "").strip()
    max_tokens = config.get("ANNOTATOR_MAX_TOKENS", 8192)
    extra_body = config.get("OPENAI_EXTRA_BODY", {})
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] Error: MCP_SERVER_URL must start with http:// or https://")
        return False, ""

    if not api_key:
        print("[AETHER] Error: OPENAI_API_KEY not set in config.")
        return False, ""

    try:
        with open(CTX_FILE_PATH, "r", encoding="utf-8") as f:
            ctx_content = f.read()
        
        # Choose prompt file based on fast mode setting
        prompt_file = PROMPT_ANNOTATOR_FAST if fast_mode else PROMPT_ANNOTATOR
        with open(prompt_file, "r", encoding="utf-8") as f:
            annotator_system_prompt = f.read()
            annotator_system_prompt = finalize_prompt(annotator_system_prompt,config)

        if fast_mode:
            print("[AETHER] [Annotator] Using fast mode (simplified output format)")
    except FileNotFoundError as e:
        print(f"[AETHER] [Annotator] Error: Required file not found: {e}. Ensure gatherer ran successfully and files are in 'ainalyse' directory.")
        return False, ""
    except Exception as e:
        print(f"[AETHER] [Annotator] Error loading files: {e}")
        return False, ""

    root_fn_name = extract_root_function_name(ctx_content)
    if root_fn_name:
        annotator_system_prompt = annotator_system_prompt.replace("{FN_NAME}", root_fn_name)
    elif "{FN_NAME}" in annotator_system_prompt:
        annotator_system_prompt = annotator_system_prompt.replace("{FN_NAME}", "the main function under analysis")

    # Extract functions list for fast mode prompt replacement
    if fast_mode and "{FUNCTIONS_LIST}" in annotator_system_prompt:
        # Extract function names from ctx_content
        functions_list = []
        
        # Parse function names from the pseudocode listing
        func_pattern = re.compile(r'^=====\n([^(]+)\([^)]*\)\s*(?:\[[^\]]+\])?\n=====', re.MULTILINE)
        for match in func_pattern.finditer(ctx_content):
            func_name = match.group(1).strip()
            if func_name:
                functions_list.append(func_name)
        
        # Convert to JSON array format for the prompt
        functions_array_str = json.dumps(functions_list)
        annotator_system_prompt = annotator_system_prompt.replace("{FUNCTIONS_LIST}", functions_array_str)
        print(f"[AETHER] [Annotator] [Fast Mode] Replaced functions list with: {functions_array_str}")

    # --- Insert custom user prompt if provided ---
    if custom_user_prompt:
        ctx_content += (
            "\n\n---\n"
            "USER-PROVIDED ADDITIONAL CONTEXT FOR ANNOTATOR:\n"
            f"{custom_user_prompt}\n"
            "---\n"
        )

    # --- VERBOSE LOGGING for Annotator ---
    try:
        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
            vf.write("\n--- Annotator System Prompt ---\n")
            vf.write(annotator_system_prompt)
            vf.write("\n--- Annotator User Prompt (Context) ---\n")
            vf.write(ctx_content)
            vf.write("\n--- END Annotator Prompts ---\n")
    except Exception as e:
        print(f"[AETHER] [Annotator] Error writing prompts to verbose.txt: {e}")

    print("[AETHER] [Annotator] Requesting annotations from LLM...")

    annotation_commands = []
    llm_full_response = ""  # For logging the full LLM output
    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [Annotator] Connected to MCP server for parsing and applying annotations.")

                try:
                    feature = "annotation"
                    client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path,feature)
                    
                    # Prepare streaming request parameters
                    request_params = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": annotator_system_prompt},
                            {"role": "user", "content": ctx_content}
                        ],
                        "max_tokens": max_tokens,
                        "temperature": 0.7,
                        "stream": True,
                        "stream_options": {
                            "include_usage": True
                        }
                    }
                    
                    # Add extra_body if provided
                    if extra_body:
                        request_params["extra_body"] = extra_body
                    
                    # Check for intranet.txt and add headers if needed
                    check_and_add_intranet_headers(request_params)
                    
                    try:
                        with client.chat.completions.create(**request_params) as stream:
                            print("[AETHER] [Annotator] Streaming LLM response and collecting suggestions...")
                            
                            # Progress indicator
                            received_tokens = 0

                            # Collect full response first, then parse all at once
                            for chunk in stream:
                                received_tokens += 1 # each chunk roughly 1 token. Need Tiktoken for better estimation
                                print(f"\r[AETHER] [Annotator] Estimated Received Tokens: {received_tokens}", end="", flush=True) 

                                if hasattr(chunk, "usage") and chunk.usage:  # Usage may arrive on every chunk, not just the final one
                                    prompt_tokens = chunk.usage.prompt_tokens
                                    completion_tokens = chunk.usage.completion_tokens
                                    total_tokens = chunk.usage.total_tokens
                                    print()
                                    print(f"[AETHER] [Annotator] Prompt tokens: {prompt_tokens}")
                                    print(f"[AETHER] [Annotator] Completion tokens: {completion_tokens}")
                                    print(f"[AETHER] [Annotator] Total tokens: {total_tokens}")

                                if not hasattr(chunk, "choices") or len(chunk.choices) == 0:
                                    continue

                                content = getattr(chunk.choices[0].delta, "content", None)
                                if content is None:
                                    continue
                                # print(content)
                                llm_full_response += content  # Accumulate for logging
                    except Exception as e:
                        print(f"[AETHER] [Annotator] IDA Stream Error: {e}")
                        
                        
                    # Parse the complete response using the new flexible method
                    all_commands = await parse_llm_annotations(
                        llm_full_response, {}, rename_filter_enabled, session, fast_mode  # Add fast_mode parameter
                    )

                    use_comments = config.get("USE_DESC", True) or config.get("USE_COMMENTS", True)
                    use_rename_vars = config.get("RENAME_VARS", True)
                    use_rename_funcs = config.get("RENAME_FUNCS", True)
                    
                    # Display what will be done
                    for command_data in all_commands:
                        cmd_type = command_data["type"]

                        # Filtering logic
                        if cmd_type == "set_comment" and not use_comments:
                            continue
                        if cmd_type == "rename_local_variable" and not use_rename_vars:
                            continue
                        if cmd_type == "rename_function" and not use_rename_funcs:
                            continue

                        if cmd_type == "set_comment":
                            print(f"[AETHER] [Annotator] Will set comment at {command_data['address']}: {command_data['comment']}")
                        elif cmd_type == "rename_local_variable":
                            print(f"[AETHER] [Annotator] Will rename local variable {command_data['old_name']} to {command_data['new_name']} in func at {command_data['function_address']}")
                        elif cmd_type == "rename_function":
                            print(f"[AETHER] [Annotator] Will rename function at {command_data['function_address']} to {command_data['new_name']}")
                    
                    # Apply all collected commands at once
                    if all_commands:
                        print("[AETHER] [Annotator] Applying analyst's suggestions...")
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            success = False
                            if cmd_type == "set_comment":
                                address = command_data["address"]
                                comment_text = command_data["comment"]
                                comment_text = comment_text.replace("<NEWLINE>", "\n")
                                wrapped_lines = []
                                for paragraph in comment_text.split('\n'):
                                    # wrap the text. width=80 is roughly 15-18 words.
                                    wrapped = textwrap.fill(paragraph, width=80, break_long_words=False)
                                    wrapped_lines.append(wrapped)
                                final_comment = "\n".join(wrapped_lines)
                                success = await mcp_execute_tool(session, "set_comment", {
                                    "address": address,
                                    "comment": final_comment
                                })
                            elif cmd_type == "rename_local_variable":
                                success = await mcp_execute_tool(session, "rename_local_variable", {
                                    "function_address": command_data["function_address"],
                                    "old_name": command_data["old_name"],
                                    "new_name": command_data["new_name"]
                                })
                            elif cmd_type == "rename_function":
                                new_name = command_data["new_name"]
                                if not command_data["new_name"].startswith("aire_"): new_name = "aire_" + new_name
                                success = await mcp_execute_tool(session, "rename_function", {
                                    "function_address": command_data["function_address"],
                                    "new_name": new_name
                                })
                            if not success:
                                print(f"[AETHER] [Annotator] Failed to apply: {command_data}")
                            # Remove the sleep delay - no longer needed with custom implementation
                        
                except Exception as e:
                    print(f"[AETHER] [Annotator] Streaming failed or not supported, falling back to batch mode: {e}")
                    # Fallback: batch mode
                    llm_response_text = call_openai_llm_annotator(annotator_system_prompt, ctx_content, api_key, model, base_url, max_tokens, extra_body, custom_ca_cert_path, client_cert_path, client_key_path)
                    llm_full_response = llm_response_text  # For logging
                    # --- VERBOSE LOGGING for Annotator Response ---
                    try:
                        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                            vf.write("\n--- Annotator LLM Response ---\n")
                            vf.write(llm_response_text if llm_response_text else "No response from LLM.")
                            vf.write("\n--- END Annotator LLM Response ---\n")
                    except Exception as e:
                        print(f"[AETHER] [Annotator] Error writing LLM response to verbose.txt: {e}")

                    if not llm_response_text:
                        print("[AETHER] [Annotator] No response from LLM.")
                        return False, ""
                        
                    all_commands = await parse_llm_annotations(
                        llm_response_text, 
                        {},  # Empty dict since we no longer use line mappings
                        rename_filter_enabled,
                        session,
                        fast_mode  # Add fast_mode parameter
                    )
                    
                    if not all_commands:
                        print("[AETHER] [Annotator] No valid annotation commands parsed or all filtered out.")
                        return True, llm_response_text

                    # Display what will be done
                    for command_data in all_commands:
                        cmd_type = command_data["type"]
                        if cmd_type == "set_comment":
                            print(f"[AETHER] [Annotator] Will set comment at {command_data['address']}: {command_data['comment']}")
                        elif cmd_type == "rename_local_variable":
                            print(f"[AETHER] [Annotator] Will rename local variable {command_data['old_name']} to {command_data['new_name']} in func at {command_data['function_address']}")
                        elif cmd_type == "rename_function":
                            print(f"[AETHER] [Annotator] Will rename function at {command_data['function_address']} to {command_data['new_name']}")
                    
                    # Apply all commands at once
                    print("[AETHER] [Annotator] Applying analyst's suggestions...")
                    for command_data in all_commands:
                        cmd_type = command_data["type"]
                        success = False
                        if cmd_type == "set_comment":
                            success = await mcp_execute_tool(session, "set_comment", {
                                "address": command_data["address"],
                                "comment": command_data["comment"]
                            })
                        elif cmd_type == "rename_local_variable":
                            success = await mcp_execute_tool(session, "rename_local_variable", {
                                "function_address": command_data["function_address"],
                                "old_name": command_data["old_name"],
                                "new_name": command_data["new_name"]
                            })
                        elif cmd_type == "rename_function":
                            success = await mcp_execute_tool(session, "rename_function", {
                                "function_address": command_data["function_address"],
                                "new_name": command_data["new_name"]
                            })
                        if not success:
                            print(f"[AETHER] [Annotator] Failed to apply: {command_data}")
                        # Remove the sleep delay - no longer needed with custom implementation
                    print("[AETHER] Changes applied successfully. You may need to refresh (F5) to see updated variable names and comments.")

                # --- Always log the full LLM response after annotation ---
                try:
                    with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                        vf.write("\n--- Annotator LLM Response ---\n")
                        vf.write(llm_full_response if llm_full_response else "No response from LLM.")
                        vf.write("\n--- END Annotator LLM Response ---\n")
                except Exception as e:
                    print(f"[AETHER] [Annotator] Error writing LLM response to verbose.txt: {e}")

                print("[AETHER] [Annotator] Annotation complete.")
                return True, llm_full_response  # Return success and output for history
    except Exception as e:
        print(f"[AETHER] [Annotator] Unexpected error during annotation application: {e}")
        traceback.print_exc()
    return False, ""
