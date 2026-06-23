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

from .tools import declare_c_struct, set_variable_type, get_struct_definition
from .util import extract_pseudocode, get_pseudocode, get_pseudocode_with_struct_comments
# --- File Paths (relative to this file's location in 'ainalyse' directory) ---
CREATOR_PROMPT = os.path.join(os.path.dirname(__file__), "prompts/struct-creator-prompt.txt")

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

def call_openai_llm_annotator(messages:list, api_key: str, model: str, base_url: str, max_tokens: int = 8192, extra_body: dict = None, custom_ca_cert_path: str = "", client_cert_path: str = "", client_key_path: str = "") -> str:
    try:
        feature = "structcon"
        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path, feature)
        
        # Prepare request parameters
        request_params = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7
        }
        
        # Add extra_body if provided
        if extra_body:
            request_params["extra_body"] = extra_body
        
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

    set_comment_pattern = re.compile(r'```declare_c_struct(?:\([^)]*\))?\s*\n(.*?)(?=\n```|$)', re.DOTALL | re.IGNORECASE)
    for match in set_comment_pattern.finditer(response_text):
        struct_def = match.group(1).strip()
        struct_name = match.group(0).split("(")[1].split(")")[0]

        field_data_lines = struct_def.split('\n')
        field_data = []
        for lines in field_data_lines:
            parts = lines.split('|')
            if len(parts) >= 3:
                name,datatype,offset = parts[0].strip(), parts[1].strip(), parts[2].strip()
                field_data.append((name,datatype,eval(offset)))
        parsed_commands.append({
                            "type": "declare_c_struct",
                            "struct_name": struct_name,
                            "c_declaration": field_data 
                        })
        print(f"[AETHER] [Annotator] Parsed declare_c_struct: {struct_name} -> {struct_def}")
    
    return parsed_commands

async def mcp_execute_tool(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> bool:
    try:
        # Handle set_comment with custom implementation instead of MCP
        if tool_name == "declare_c_struct":
            struct_name = params.get("struct_name","")
            c_decl = params.get("c_declaration",[])
            return_container = {'ret': None}
            def _declare_c_struct_sync():
                try:
                    return_container['ret'] = declare_c_struct(struct_name,c_decl)
                    return True
                except Exception as e:
                    print(f"[AETHER] Error creating type {struct_name}: {e}")
                    return False
            ida_kernwin.execute_sync(_declare_c_struct_sync, ida_kernwin.MFF_WRITE)
            return return_container['ret']
        else:
            # Use MCP for other tools
            await session.call_tool(tool_name, params if params else {})
            return True
    except Exception as e:
        print(f"[AETHER] Error calling tool {tool_name} with params {params}: {e}")
        return False


def init_prompt():
    try:
        # Choose prompt file based on fast mode setting
        prompt_file = CREATOR_PROMPT
        with open(prompt_file, "r", encoding="utf-8") as f:
            creator_system_prompt = f.read()
            
    except FileNotFoundError as e:
        print(f"[AETHER] [Annotator] Error: Required file not found: {e}. Ensure gatherer ran successfully and files are in 'ainalyse' directory.")
        return None
    except Exception as e:
        print(f"[AETHER] [Annotator] Error loading files: {e}")
        return None
    return creator_system_prompt

def replace_prompt(creator_system_prompt, struct_name, func_graph, struct_list, comment_dict):
    func_graph_str = ""
    for func, var_list in func_graph.items():
        for var_name,offset,struct_type in var_list: 
            func_graph_str += f"|{func} |{var_name} |{offset} |\n"

    creator_system_prompt = creator_system_prompt.replace("{FUNC_GRAPH}", func_graph_str)
    creator_system_prompt = creator_system_prompt.replace("{STRUCT_NAME}", struct_name)
    struct_def_list = {}
    for struct in struct_list:
        def _get_struct_definition_sync():
            name, fields = get_struct_definition(struct)
            struct_def_list[name] = fields
            return True
        ida_kernwin.execute_sync(_get_struct_definition_sync, ida_kernwin.MFF_WRITE)
    struct_def_str = ""
    for struct, fields in struct_def_list.items():
        struct_def_str += f"struct {struct}" + "{\n"
        for t,name,offset in fields:
            struct_def_str += f"{t} {name}; # offset: {hex(offset)}\n"
        struct_def_str += "}\n\n"
        
    creator_system_prompt = creator_system_prompt.replace("{STRUCT_LIST}", struct_def_str)

    func_code_list = []
    for func in func_graph.keys():
        code_container = {}
        code_container['code'] = None


        def _get_pseudocode_sync():
            fname = func
            code_container['code'] = get_pseudocode_with_struct_comments(fname,comment_dict)
            return True

        ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_WRITE)

        
        func_code = code_container['code']

        if not func_code is None:
            func_code_list.append(func_code)
        else:
            print(f"[AETHER] [Creator] Error: Function not found: {func}")
    # Convert to JSON array format for the prompt
    functions_array_str = json.dumps(func_code_list)
    
    return creator_system_prompt, functions_array_str



async def run_creator_agent(config: dict, struct_name:str, func_graph:dict, struct_list:list, comment_dict:dict):
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
    
    creator_system_prompt = init_prompt()
    if creator_system_prompt is None:
        return False,""

    creator_system_prompt, functions_array_str = replace_prompt(creator_system_prompt, struct_name, func_graph, struct_list, comment_dict)

    # --- VERBOSE LOGGING for Annotator ---
    try:
        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
            vf.write("\n--- Annotator System Prompt ---\n")
            vf.write(creator_system_prompt)
            vf.write("\n--- Annotator User Prompt (Context) ---\n")
            vf.write(functions_array_str)
            vf.write("\n--- END Annotator Prompts ---\n")
    except Exception as e:
        print(f"[AETHER] [Creator] Error writing prompts to verbose.txt: {e}")

    print("[AETHER] [Creator] Requesting annotations from LLM...")

    #print(annotator_system_prompt)
    annotation_commands = []
    llm_full_response = ""  # For logging the full LLM output
    messages = [
                {"role": "system", "content": creator_system_prompt},
                {"role": "user", "content": functions_array_str}
    ]
    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [Creator] Connected to MCP server for parsing and applying annotations.")

                try:
                    feature = "structcon"
                    client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path, feature)

                    # Prepare streaming request parameters
                    request_params = {
                        "model": model,
                        "messages": messages,
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
                    
                    stream = client.chat.completions.create(**request_params)
                    print("[AETHER] [Creator] Streaming LLM response and collecting suggestions...")
                    
                    # Progress indicator
                    received_tokens = 0

                    # Collect full response first, then parse all at once
                    for chunk in stream:
                        if hasattr(chunk, "usage") and chunk.usage: # Final chunk with usage info
                            prompt_tokens = chunk.usage.prompt_tokens
                            completion_tokens = chunk.usage.completion_tokens
                            total_tokens = chunk.usage.total_tokens
                            print()
                            print(f"[AETHER] [Creator] Prompt tokens: {prompt_tokens}")
                            print(f"[AETHER] [Creator] Completion tokens: {completion_tokens}")
                            print(f"[AETHER] [Creator] Total tokens: {total_tokens}")
                            continue  # skip further processing for final chunk

                        content = getattr(chunk.choices[0].delta, "content", None)
                        if content is None:
                            continue
                        # print(content)
                        llm_full_response += content  # Accumulate for logging
                        received_tokens += 1 # each chunk roughly 1 token. Need Tiktoken for better estimation
                        print(f"\r[AETHER] [Creator] Estimated Received Tokens: {received_tokens}", end="", flush=True) 
                        
                    # Parse the complete response using the new flexible method
                    all_commands = await parse_llm_annotations(
                        llm_full_response, {}, rename_filter_enabled, session  
                    )
                    
                    # Display what will be done
                    for command_data in all_commands:
                        cmd_type = command_data["type"]
                        if cmd_type == "declare_c_struct":
                            print(f"[AETHER] [Creator] Will create C struct {command_data['c_declaration']}")
                    failed_struct = {}
                    # Apply all collected commands at once
                    if all_commands:
                        print("[AETHER] [Creator] Applying analyst's suggestions...")
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            success = False

                            if cmd_type == "declare_c_struct":
                                failed_list = await mcp_execute_tool(session, "declare_c_struct", {
                                    "struct_name": command_data["struct_name"],
                                    "c_declaration": command_data["c_declaration"]
                                })
                                if len(failed_list)>0:
                                    failed_struct[command_data["struct_name"]] = failed_list

                            # Remove the sleep delay - no longer needed with custom implementation

                    # Throw back to LLM to create datatype that have failed
                    if len(failed_struct) > 0:
                        print(f"Failed Struct: {str(failed_struct)}")
                        missing_struct = set()
                        for failed, fields in failed_struct.items():
                            missing_struct = missing_struct.union(fields)
                        follow_up_prompt = f"""You have declared the struct in the wrong order or the following struct types are missing from your declaration:

{str(missing_struct)}

You are to only call declare_c_struct for the missing struct types only. You must not need to call declare_c_struct for the structs you have called previously or redefined the structs you have identified earlier.

If it is the case of wrong order, you can reply with a nil response.
"""
                        messages.append({"role": "user", "content": follow_up_prompt})
                        llm_response_text = call_openai_llm_annotator(messages, api_key, model, base_url, max_tokens, extra_body, custom_ca_cert_path, client_cert_path, client_key_path)

                        try:
                            with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                                vf.write("\n--- Follow-Up LLM Response ---\n")
                                vf.write(llm_response_text if llm_response_text else "No response from LLM.")
                                vf.write("\n--- END Follow-Up LLM Response ---\n")
                        except Exception as e:
                            print(f"[AETHER] [Creator-Follow-Up] Error writing LLM response to verbose.txt: {e}")
                            
                        if not llm_response_text:
                            print("[AETHER] [Creator-Follow-Up] No response from LLM.")
                            return False, ""    
                        all_commands = await parse_llm_annotations(
                            llm_response_text, 
                            {},  # Empty dict since we no longer use line mappings
                            rename_filter_enabled,
                            session,
                            fast_mode  # Add fast_mode parameter
                        )
                        if not all_commands:
                            print("[AETHER] [Creator] No valid annotation commands parsed or all filtered out.")
                            return True, llm_response_text
                        failed_struct = {}
                        # Display what will be done
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            if cmd_type == "declare_c_struct":
                                print(f"[AETHER] [Creator] Will create C struct {command_data['c_declaration']}")
                        
                        # Apply all commands at once
                        print("[AETHER] [Creator-Follow-Up] Applying analyst's suggestions...")
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            success = False

                            if cmd_type == "declare_c_struct":
                                
                                failed_list = await mcp_execute_tool(session, "declare_c_struct", {
                                    "struct_name": command_data["struct_name"],
                                    "c_declaration": command_data["c_declaration"]
                                })
                                if len(failed_list)>0:
                                    failed_struct[command_data["struct_name"]] = failed_list
                        # Recreate failed fields
                        for failed, fields in failed_struct.items():
                            failed_list = await mcp_execute_tool(session, "declare_c_struct", {
                                    "struct_name": failed,
                                    "c_declaration": fields
                            })
                            
                except Exception as e:
                    print(f"[AETHER] [Creator] Streaming failed or not supported, falling back to batch mode: {e}")
                    # Fallback: batch mode
                    messages = [
                        {"role": "system", "content": creator_system_prompt},
                        {"role": "user", "content": functions_array_str}
                    ]
                    llm_response_text = call_openai_llm_annotator(messages, api_key, model, base_url, max_tokens, extra_body, custom_ca_cert_path, client_cert_path, client_key_path)
                    messages.append({"role": "assistant", "content": llm_response_text})
                    llm_full_response = llm_response_text  # For logging
                    # --- VERBOSE LOGGING for Annotator Response ---
                    try:
                        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                            vf.write("\n--- Creator LLM Response ---\n")
                            vf.write(llm_response_text if llm_response_text else "No response from LLM.")
                            vf.write("\n--- END Creator LLM Response ---\n")
                    except Exception as e:
                        print(f"[AETHER] [Creator] Error writing LLM response to verbose.txt: {e}")

                    if not llm_response_text:
                        print("[AETHER] [Creator] No response from LLM.")
                        return False, ""
                        
                    all_commands = await parse_llm_annotations(
                        llm_response_text, 
                        {},  # Empty dict since we no longer use line mappings
                        rename_filter_enabled,
                        session,
                        fast_mode  # Add fast_mode parameter
                    )
                    
                    if not all_commands:
                        print("[AETHER] [Creator] No valid annotation commands parsed or all filtered out.")
                        return True, llm_response_text
                    failed_struct = {}
                    # Display what will be done
                    for command_data in all_commands:
                        cmd_type = command_data["type"]
                        if cmd_type == "declare_c_struct":
                            print(f"[AETHER] [Creator] Will create C struct {command_data['c_declaration']}")
                    
                    # Apply all commands at once
                    print("[AETHER] [Creator] Applying analyst's suggestions...")
                    for command_data in all_commands:
                        cmd_type = command_data["type"]

                        if cmd_type == "declare_c_struct":
                            
                            failed_list = await mcp_execute_tool(session, "declare_c_struct", {
                                "struct_name": command_data["struct_name"],
                                "c_declaration": command_data["c_declaration"]
                            })
                            failed_struct[command_data["struct_name"]] = failed_list

                        # Remove the sleep delay - no longer needed with custom implementation
                    print("[AETHER] Changes applied successfully. You may need to refresh (F5) to see updated variable names and comments.")

                    # --- Always log the full LLM response after annotation ---
                    try:
                        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                            vf.write("\n--- Annotator LLM Response ---\n")
                            vf.write(llm_full_response if llm_full_response else "No response from LLM.")
                            vf.write("\n--- END Annotator LLM Response ---\n")
                    except Exception as e:
                        print(f"[AETHER] [Creator] Error writing LLM response to verbose.txt: {e}")

                    if len(failed_struct) > 0:
                        print(f"[AETHER] [Creator] Failed to create struct fields: {str(failed_struct)}")
                        missing_struct = set()
                        for failed, fields in failed_struct.items():
                            missing_struct = missing_struct.union(fields)
                        follow_up_prompt = f"""You have declared the struct in the wrong order or the following struct types are missing from your declaration:

{str(missing_struct)}

You are to only call declare_c_struct for the missing struct types only. You must not need to call declare_c_struct for the structs you have called previously or redefined the structs you have identified earlier.

If it is the case of wrong order, you can reply with a nil response.
"""
                        messages.append({"role": "user", "content": follow_up_prompt})
                        llm_response_text = call_openai_llm_annotator(messages, api_key, model, base_url, max_tokens, extra_body, custom_ca_cert_path, client_cert_path, client_key_path)

                        try:
                            with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                                vf.write("\n--- Follow-Up LLM Response ---\n")
                                vf.write(llm_response_text if llm_response_text else "No response from LLM.")
                                vf.write("\n--- END Follow-Up LLM Response ---\n")
                        except Exception as e:
                            print(f"[AETHER] [Creator-Follow-Up] Error writing LLM response to verbose.txt: {e}")
                            
                        if not llm_response_text:
                            print("[AETHER] [Creator-Follow-Up] No response from LLM.")
                            return False, ""    
                        all_commands = await parse_llm_annotations(
                            llm_response_text, 
                            {},  # Empty dict since we no longer use line mappings
                            rename_filter_enabled,
                            session,
                            fast_mode  # Add fast_mode parameter
                        )
                        if not all_commands:
                            print("[AETHER] [Creator-Follow-Up] No valid annotation commands parsed or all filtered out.")
                            return True, llm_response_text
                        
                        # Display what will be done
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            if cmd_type == "declare_c_struct":
                                print(f"[AETHER] [Creator-Follow-Up] Will create C struct {command_data['c_declaration']}")
                        
                        # Apply all commands at once
                        print("[AETHER] [Creator-Follow-Up] Applying analyst's suggestions...")
                        for command_data in all_commands:
                            cmd_type = command_data["type"]
                            success = False

                            if cmd_type == "declare_c_struct":
                                
                                failed_list = await mcp_execute_tool(session, "declare_c_struct", {
                                    "struct_name": command_data["struct_name"],
                                    "c_declaration": command_data["c_declaration"]
                                })
                                #failed_struct[command_data["struct_name"]] = failed_list

                        for failed, fields in failed_struct.items():
                            failed_list = await mcp_execute_tool(session, "declare_c_struct", {
                                    "struct_name": failed,
                                    "c_declaration": fields
                            })


                for func, var_list in func_graph.items():
                    for var_name,offset,struct_type in var_list:
                        if offset == 0:
                            print(f"[AETHER] [Creator] Setting data type for {func}: {var_name} -> {struct_name} {struct_type}")
                            def _set_variable_type_sync():
                                if struct_type == 'struct':
                                    set_variable_type(func, var_name, struct_name)
                                else:
                                    set_variable_type(func, var_name, struct_name + "*")
                                return True
                            ida_kernwin.execute_sync(_set_variable_type_sync, ida_kernwin.MFF_WRITE)
                print("[AETHER] [Creator] Annotation complete.")
                return True, llm_full_response  # Return success and output for history
            
    except Exception as e:
        print(f"[AETHER] [Creator] Unexpected error during annotation application: {e}")
        traceback.print_exc()
    return False, ""
