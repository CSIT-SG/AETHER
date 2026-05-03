import ida_kernwin
import os
import json
import re
import traceback
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from openai import OpenAI
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from ainalyse.custom_set_cmt import scmt  # Import custom set_comment implementation
from ainalyse.utils import check_and_add_intranet_headers

from .tools import declare_c_struct
from .util import extract_pseudocode

# --- File Paths (relative to this file's location in 'ainalyse' directory) ---
PROMPT_ANNOTATOR = os.path.join(os.path.dirname(__file__), "prompts/struct-nested-identifier-prompt.txt")
PROMPT_ANNOTATOR_FAST = os.path.join(os.path.dirname(__file__), "prompts/struct-nested-identifier-prompt.txt")

# Use lazy initialization to avoid circular import
CTX_FILE_PATH = None
VERBOSE_LOG_PATH = None

def _init_paths():
    """Initialize file paths lazily to avoid circular imports"""
    global CTX_FILE_PATH, VERBOSE_LOG_PATH
    if CTX_FILE_PATH is None:
        from ainalyse import get_data_directory
        data_dir = get_data_directory()
        CTX_FILE_PATH = os.path.join(data_dir, "struct_ctx.txt")
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
        feature = "structcon"
        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path, feature)
        
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
    
    response_text = response_text +"\n\n"
    set_comment_pattern = re.compile(r'```declare_struct(?:\([^)]*\))?\s*\n(.*?)(?=\n```|$)', re.DOTALL | re.IGNORECASE)
    for match in set_comment_pattern.finditer(response_text):
        print(match.group(0))
        struct_name = match.group(0).split("(")[1].split(")")[0]
        lines_str = match.group(1).strip()
        
        for line_entry in lines_str.split('\n'):
            line_entry = line_entry.strip()
            if not line_entry:
                continue

            parts = line_entry.split('|')
            if len(parts) >= 4:
                function_name, variable_name, offset, struct_type = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
                if function_name and variable_name:
                    parsed_commands.append({
                        "type": "declare_struct",
                        "struct_name": struct_name,
                        "function_name": function_name,
                        "variable_name": variable_name,
                        "offset" : eval(offset),
                        "struct_type" : struct_type
                    })
                    print(f"[AETHER] [Struct Identifier] Parsed declare_struct: {struct_name} -> {function_name}, {variable_name}")
            else:
                print(f"[AETHER] [Struct Identifier] Malformed declare_struct line: '{line_entry}'. Skipping.")
                    
    set_comment_pattern = re.compile(r'```declare_struct_size\s*\n(.*?)(?=\n```|$)', re.DOTALL | re.IGNORECASE)
    for match in set_comment_pattern.finditer(response_text):
        lines_str = match.group(1).strip()

        for line_entry in lines_str.split('\n'):
            line_entry = line_entry.strip()
            if not line_entry:
                continue

            parts = line_entry.split('|', 1)
            if len(parts) >= 2:
                struct_name, struct_size = parts[0].strip(), parts[1].strip()
                if struct_name and struct_size:
                    parsed_commands.append({
                        "type": "declare_struct_size",
                            "struct_name": struct_name,
                            "struct_size": eval(struct_size) 
                    })
                    print(f"[AETHER] [Struct Identifier] Parsed declare_struct_size: {struct_name} -> {struct_size}")
            else:
                print(f"[AETHER] [Struct Identifier] Malformed declare_struct line: '{line_entry}'. Skipping.")

    return parsed_commands


async def mcp_execute_tool(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> bool:
    return True
    try:
        # Handle set_comment with custom implementation instead of MCP
        if tool_name == "declare_struct":
            struct_name = params.get("struct_name", "")
            func_name = params.get("function_name", "")
            variable_name = params.get("variable_name", "")
            
            # Execute custom set_comment on main thread
            def _set_comment_sync():
                try:
                    scmt(address, comment)
                    return True
                except Exception as e:
                    print(f"[AETHER] Error setting comment at {address}: {e}")
                    return False
            
            return ida_kernwin.execute_sync(_set_comment_sync, ida_kernwin.MFF_WRITE)
        elif tool_name == "declare_struct_size":
            struct_name = params.get("struct_name","")
            c_decl = params.get("c_declaration",[])
            def _declare_c_struct_sync():
                try:
                    declare_c_struct(struct_name,c_decl)
                    return True
                except Exception as e:
                    print(f"[AETHER] Error creating type {struct_name}: {e}")
                    return False
            return ida_kernwin.execute_sync(_declare_c_struct_sync, ida_kernwin.MFF_WRITE)
        else:
            # Use MCP for other tools
            #await session.call_tool(tool_name, params if params else {})
            return True
    except Exception as e:
        print(f"[AETHER] Error calling tool {tool_name} with params {params}: {e}")
        return False

def extract_root_function_name(ctx_content: str) -> Optional[str]:
    match = re.search(r"FINAL CALL TREE:\n(.*?)\s*\[", ctx_content)
    if match:
        return match.group(1).strip()
    return None

async def run_identifier_agent(config: dict, variable_name:str):
    _init_paths()  # Initialize file paths lazily to avoid circular imports
    
    server_url = config["MCP_SERVER_URL"]
    api_key = config["OPENAI_API_KEY"]
    model = config["ANNOTATOR_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    rename_filter_enabled = config.get("rename_filter_enabled", False)
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

    annotator_system_prompt = annotator_system_prompt.replace("{VARIABLE}", variable_name)
    functions_list = []
    # Extract functions list for fast mode prompt replacement
    if fast_mode and "{FUNCTIONS_LIST}" in annotator_system_prompt:

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
                    feature = "structcon"
                    client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path, feature)
                    
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
                    
                    stream = client.chat.completions.create(**request_params)
                    print("[AETHER] [Annotator] Streaming LLM response and collecting suggestions...")
                    
                    # Progress indicator
                    received_tokens = 0

                    # Collect full response first, then parse all at once
                    for chunk in stream:
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
                        received_tokens += 1 # each chunk roughly 1 token. Need Tiktoken for better estimation
                        print(f"\r[AETHER] [Annotator] Estimated Received Tokens: {received_tokens}", end="", flush=True) 
                        
                    # Parse the complete response using the new flexible method
                    all_commands = await parse_llm_annotations(
                        llm_full_response, {}, rename_filter_enabled, session, fast_mode  # Add fast_mode parameter
                    )
                    sub_graph = {}
                    declared_struct = []
                    # Apply all collected commands at once
                    if all_commands:
                        print("[AETHER] [Annotator] Applying analyst's suggestions...")
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            success = False

                            if cmd_type == "declare_struct":
                                struct_name = command_data["struct_name"]
                                function_name = command_data["function_name"]
                                variable_name = command_data["variable_name"]
                                offset = command_data["offset"]
                                struct_type = command_data["struct_type"]
                                if not struct_name in sub_graph:
                                    sub_graph[struct_name] = {}
                                
                                if not function_name in sub_graph[struct_name]:
                                    sub_graph[struct_name][function_name] = []

                                sub_graph[struct_name][function_name].append((variable_name,offset,struct_type))
                            elif cmd_type == "declare_struct_size":
                                declared_struct.append((command_data["struct_name"],command_data["struct_size"]))


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

                    # Apply all commands at once
                    print("[AETHER] [Annotator] Applying analyst's suggestions...")
                    sub_graph = {}
                    declared_struct = []
                    for command_data in all_commands:
                        cmd_type = command_data["type"]
                        success = False

                        if cmd_type == "declare_struct":
                            struct_name = command_data["struct_name"]
                            function_name = command_data["function_name"]
                            variable_name = command_data["variable_name"]
                            offset = command_data["offset"]
                            struct_type = command_data["struct_type"]
                            if not struct_name in sub_graph:
                                sub_graph[struct_name] = {}
                            
                            if not function_name in sub_graph[struct_name]:
                                sub_graph[struct_name][function_name] = []

                            sub_graph[struct_name][function_name].append((variable_name,offset,struct_type))
                        elif cmd_type == "declare_struct_size":
                            declared_struct.append((command_data["struct_name"],command_data["struct_size"]))

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
                return True, llm_full_response, sub_graph, declared_struct  # Return success and output for history
    except Exception as e:
        print(f"[AETHER] [Annotator] Unexpected error during annotation application: {e}")
        traceback.print_exc()
    return False, "", None, None


