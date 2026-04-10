import os
import re
from datetime import datetime
import time
import textwrap
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import ida_kernwin
import idaapi
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
import tiktoken

from ainalyse import finalize_prompt, load_config
from ainalyse.custom_set_cmt import scmt
from ainalyse.function_selection import collect_functions_with_default_criteria
from ainalyse.manual_gatherer import Node, format_call_tree_ascii
from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from ainalyse.utils import refresh_functions

# File paths
REALTIME_PROMPT_FILE = os.path.join(os.path.dirname(__file__), "..", "prompts", "realtime-annotator-fast.txt")
CORRECTION_PROMPT_FILE = os.path.join(os.path.dirname(__file__), "..", "prompts", "realtime-annotator-correction.txt")

async def mcp_get_tool_text_content(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> Optional[str]:
    """Helper to get text content from MCP tools."""
    try:
        res = await session.call_tool(tool_name, params if params else {})
        if res.content and res.content[0] and hasattr(res.content[0], 'text'):
            return res.content[0].text
    except Exception as e:
        print(f"[AETHER] [Fast Look] Error calling MCP tool {tool_name}: {e}")
    return None

def call_openai_llm_realtime(system_prompt: str, user_prompt: str, api_key: str, model: str, base_url: str, system_prompt_at_bottom: bool, prompt_token_warning: int, extra_body: dict = None, custom_ca_cert_path: str = "", client_cert_path: str = "", client_key_path: str = "", debug: bool = False, task: str = "") -> str:
    """Call OpenAI API for realtime analysis."""
    try:
        # Estimate tokens generated for user prompt
        os.environ["TIKTOKEN_CACHE_DIR"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "\encodings"
        enc = tiktoken.get_encoding("r50k_base")
        print("[AETHER] [LLM] Estimated Tokens Generated: "+str(len(enc.encode(user_prompt + system_prompt))))
        if len(enc.encode(user_prompt + system_prompt)) > prompt_token_warning:
            print(f"[AETHER] [LLM] Pseudo Code sent may be cut due to being too long.")
    except Exception as e:
        print(f"[AETHER] [LLM] Error estimating tokens generated: {e}")
    try:
        config = load_config()
        max_tokens = config.get("ANNOTATOR_MAX_TOKENS", 30000)
        feature = "annotation"
        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path,feature)
        
        # Append "/no_think" to user message
        user_message_content = user_prompt + "/no_think"
        if system_prompt_at_bottom:
            messages =[{"role": "user", "content": user_message_content}, {"role": "system", "content": system_prompt}]
        else:
            messages =[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message_content}]
        request_params = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": 0.7,
            }
        
        if extra_body:
            request_params["extra_body"] = extra_body

        
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if debug:
            with open(f"{task}_{current_time}.txt", "w", encoding='utf-8') as outputfile:
                outputfile.write("SYSTEM PROMPT:\n" + system_prompt)
                outputfile.write("\n\nUSER PROMPT:\n" + user_prompt)
                outputfile.write("\n\nRESPONSE:\n")
        response = client.chat.completions.create(**request_params)
        if (response.choices[0].message.content):
            if debug:
                with open(f"{task}_{current_time}.txt", "a", encoding='utf-8') as outputfile:
                    outputfile.write(response.choices[0].message.content.strip())
            return response.choices[0].message.content.strip()
        else:
            if debug:
                with open(f"{task}_{current_time}.txt", "a", encoding='utf-8') as outputfile:
                    outputfile.write("No response")
            return
    except Exception as e:
        if debug:
            with open(f"{task}_{current_time}.txt", "a", encoding='utf-8') as outputfile:
                outputfile.write(f"{e}")
        print(f"[AETHER] [Fast Look] Error calling OpenAI API: {e}")
        return ""

def parse_realtime_response(response_text: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Parse the realtime annotator response format."""
    comments = []
    local_variables = []
    function_renames = []
    
    # Parse comments block
    comments_pattern = re.compile(r'```comments\s*\n(.*?)(?:\n```|$)', re.DOTALL | re.IGNORECASE)
    comments_match = comments_pattern.search(response_text)
    if comments_match:
        comments_block = comments_match.group(1).strip()
        for line in comments_block.split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('|', 1)
            if len(parts) >= 2:
                address, comment_text = parts[0].strip(), parts[1].strip()
                if address and comment_text:
                    comment_text = comment_text.replace("<NEWLINE>", "\n")
                    wrapped_lines = []
                    for paragraph in comment_text.split('\n'):
                        # wrap the text. width=80 is roughly 15-18 words.
                        wrapped = textwrap.fill(paragraph, width=80, break_long_words=False)
                        wrapped_lines.append(wrapped)
                    final_comment = "\n".join(wrapped_lines)
                    comments.append({
                        "address": address,
                        "comment": final_comment
                    })
    
    # Parse local_variables block
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
    r'^_?(_.*_)?([XYZ]MM\d{1,5}|ST\d|Q\d{1,2}|D\d{1,2})$'
    # Common Generic Short-hands
    r'^(s|n|i|j|k|fd|pid|name|flags|src|dest|buf|ptr|len|res|ret|status|val)$|'
    # Result and Stack Metadata
    r'^result$|^savedregs$|^anonymous_\d+$|',
    re.IGNORECASE
    )
    variables_pattern = re.compile(r'```local_variables\s*\n(.*?)(?:\n```|$)', re.DOTALL | re.IGNORECASE)
    variables_match = variables_pattern.search(response_text)
    if variables_match:
        variables_block = variables_match.group(1).strip()
        for line in variables_block.split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('|', 1)
            if len(parts) >= 2:
                old_name, new_name = parts[0].strip(), parts[1].strip()
                if IDA_DUMMY_VAR_RE.match(old_name):
                    if old_name and new_name:
                        local_variables.append({
                            "old_name": old_name,
                            "new_name": new_name
                        })
                else:
                    print(f"[AETHER] [Realtime] Skipping rename of variable '{old_name}' to '{new_name}' due to filter (not a default pattern like v1 or a1).")
    
    # Parse function_renames block
    IDA_DUMMY_FUNC_RE = re.compile(r'^(aire_|sub|nullsub|loc|unk|off|asc|byte|word|dword|qword|j|__imp|__wrapper)_[0-9a-fA-F]+$', re.IGNORECASE)
    functions_pattern = re.compile(r'```function_renames\s*\n(.*?)(?:\n```|$)', re.DOTALL | re.IGNORECASE)
    functions_match = functions_pattern.search(response_text)
    if functions_match:
        functions_block = functions_match.group(1).strip()
        for line in functions_block.split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('|', 1)
            if len(parts) >= 2:
                old_name, new_name = parts[0].strip(), parts[1].strip()
                if IDA_DUMMY_FUNC_RE.match(old_name):
                    if old_name and new_name:
                        function_renames.append({
                            "old_name": old_name,
                            "new_name": new_name
                        })
                else:
                    print(f"[AETHER] [Realtime] Skipping rename of function '{old_name}' to '{new_name}' due to filter (current name does not start with 'sub_').")
    return comments, local_variables, function_renames

async def mcp_execute_realtime_action(session: ClientSession, action_type: str, params: Dict) -> bool:
    """Execute actions through MCP or custom implementation."""
    try:
        if action_type == "set_comment":
            address = params.get("address", "")
            comment = params.get("comment", "")
            
            def _set_comment_sync():
                try:
                    scmt(address, comment)
                    return True
                except Exception as e:
                    print(f"[AETHER] [Fast Look] Error setting comment at {address}: {e}")
                    return False
            
            return ida_kernwin.execute_sync(_set_comment_sync, ida_kernwin.MFF_WRITE)
        else:
            # Use MCP for other tools
            await session.call_tool(action_type, params)
            return True
    except Exception as e:
        print(f"[AETHER] [Fast Look] Error executing {action_type}: {e}")
        return False

def strip_and_reformat_pseudocode_for_realtime(pseudocode: str) -> str:
    """Clean pseudocode for realtime analysis."""
    import re
    config = load_config()
    comment_every_line = config.get("COMMENT_EVERY_LINE", False)
    # Path 1
    lines = pseudocode.splitlines()
    result = []
    line_re = re.compile(r'^\s*/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*/\s*(.*)$')
    
    for line in lines:
        if line.strip().startswith('cannotComment|') or re.match(r'^\s*0x[0-9a-fA-F]+\|', line):
            result.append(line)
            continue
            
        m = line_re.match(line)
        if m:
            address = m.group(2)
            code = m.group(3)
            if address:
                result.append(f"{address}| {code}")
            else:
                result.append(f"cannotComment| {code}")
        else:
            if line.strip():
                result.append(f"cannotComment| {line}")
            else:
                result.append(line)
    return "\n".join(result)

def format_pseudocode_listing_for_realtime(pseudocode_store: Dict[str, str]) -> str:
    """Format pseudocode listing for realtime analysis."""
    if not pseudocode_store:
        return "FUNCTIONS PSEUDOCODE:\n\nNo pseudocode collected yet."
    listing = "FUNCTIONS PSEUDOCODE:\n"
    for func_name, code in pseudocode_store.items():
        formatted_code = strip_and_reformat_pseudocode_for_realtime(code)
        listing += f"\n=====\n{func_name}(...)\n=====\n\n{formatted_code.strip()}\n"
    return listing

async def run_realtime_analysis_common(config: dict, current_func_name: str, current_func_addr: str, prompt_file: str, smart_select: bool, prompt_replacements: dict = None) -> bool:
    """Common function for running realtime analysis with different prompts."""
    start_time = time.time()
    
    server_url = config["MCP_SERVER_URL"]
    api_key = config["OPENAI_API_KEY"]
    # Use SINGLE_ANALYSIS_MODEL for realtime analysis, fall back to OPENAI_MODEL if not set
    model = config.get("SINGLE_ANALYSIS_MODEL") or config["OPENAI_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    system_prompt_at_bottom = config.get("SYSTEM_PROMPT_AT_BOTTOM", False)
    prompt_token_warning = config.get("PROMPT_TOKEN_WARNING", 64000)
    extra_body = config.get("OPENAI_EXTRA_BODY", {})
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")
    debug = config.get("DEBUG", False)

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] [Realtime] Error: MCP_SERVER_URL must start with http:// or https://")
        return False, None, None, None

    if not api_key:
        print("[AETHER] [Realtime] Error: OPENAI_API_KEY not set in config.")
        return False, None, None, None

    print(f"[AETHER] [Realtime] Using model: {model}")

    # Test MCP connection first before proceeding
    from ainalyse import test_mcp_connection
    print("[AETHER] [Realtime] Testing MCP connection...")
    mcp_success, mcp_msg = await test_mcp_connection(server_url)
    if not mcp_success:
        print(f"[AETHER] [Realtime] MCP connection failed: {mcp_msg}")
        return False, None, None, None
    print("[AETHER] [Realtime] MCP connection test successful")

    try:
        # Load prompt file
        with open(prompt_file, "r", encoding="utf-8") as f:
            system_prompt = f.read()
    except FileNotFoundError:
        print(f"[AETHER] [Realtime] Error: Prompt file not found at {prompt_file}")
        return False, None, None, None

    # Apply option for commenting
    system_prompt = finalize_prompt(system_prompt)

    # Apply standard replacements first
    system_prompt = system_prompt.replace("ROOT_FUNCTION_NAME", current_func_name)
    
    # Apply additional replacements if provided
    if prompt_replacements:
        for placeholder, replacement in prompt_replacements.items():
            system_prompt = system_prompt.replace(placeholder, replacement)
            print(f"[AETHER] [Realtime] Applied replacement: {placeholder} -> {replacement[:100]}{'...' if len(replacement) > 100 else ''}")

    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [Realtime] Connected to MCP server.")

                # Use manual gatherer defaults logic to collect functions
                selected_functions_container = {"functions": []}
                
                def _collect_functions_sync():
                    try:
                        result = collect_functions_with_default_criteria(
                            current_func_addr, current_func_name, 
                            depth=0, max_depth=5
                        )
                        selected_functions_container["functions"] = result
                        return len(result)
                    except Exception as e:
                        print(f"[AETHER] [Realtime] Error in function collection: {e}")
                        selected_functions_container["functions"] = []
                        return 0
                
                ida_kernwin.execute_sync(_collect_functions_sync, ida_kernwin.MFF_READ)
                selected_functions = selected_functions_container["functions"]
                
                print(f"[AETHER] [Realtime] Collected {len(selected_functions)} functions for analysis")

                # Build call tree and pseudocode (same logic for both modes)
                pseudocode_store = {}
                processed_functions = set()
                call_tree_root = Node(name=current_func_name, address=current_func_addr)
                
                # Get call relationships
                call_relationships = {}
                relationships_container = {"relationships": {}}
                
                def _get_call_relationships_sync():
                    try:
                        import idautils
                        import idc
                        
                        relationships = {}
                        for func_info in selected_functions:
                            func_name = func_info["name"]
                            func_addr = func_info["address"]
                            
                            try:
                                func_addr_int = int(func_addr, 16)
                                func = idaapi.get_func(func_addr_int)
                                if not func:
                                    continue
                                
                                callee_functions = set()
                                for instruction_ea in idautils.FuncItems(func.start_ea):
                                    for xref in idautils.XrefsFrom(instruction_ea, 0):
                                        callee_func = idaapi.get_func(xref.to)
                                        if callee_func:
                                            callee_functions.add(callee_func.start_ea)
                                
                                callees = []
                                for func_ea in callee_functions:
                                    callee_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                                    if callee_name and any(f["name"] == callee_name for f in selected_functions):
                                        callees.append(callee_name)
                                
                                if callees:
                                    relationships[func_name] = callees
                                    
                            except Exception as e:
                                print(f"[AETHER] [Realtime] Error getting callees for {func_name}: {e}")
                        
                        relationships_container["relationships"] = relationships
                        return True
                    except Exception as e:
                        print(f"[AETHER] [Realtime] Error in call relationship gathering: {e}")
                        return False
                
                ida_kernwin.execute_sync(_get_call_relationships_sync, ida_kernwin.MFF_READ)
                call_relationships = relationships_container["relationships"]
                
                # Build hierarchical tree
                def build_tree_recursive(parent_node, parent_func_name, processed_nodes):
                    if parent_func_name in processed_nodes:
                        return
                    
                    processed_nodes.add(parent_func_name)
                    callees = call_relationships.get(parent_func_name, [])
                    
                    if not isinstance(callees, list):
                        callees = []
                    
                    for callee_name in callees:
                        callee_addr = None
                        for func_info in selected_functions:
                            if func_info['name'] == callee_name:
                                callee_addr = func_info['address']
                                break
                        
                        if callee_addr:
                            child_exists = any(child.name == callee_name for child in parent_node.children)
                            if not child_exists:
                                child_node = Node(name=str(callee_name), address=str(callee_addr), parent_name=str(parent_func_name))
                                parent_node.add_child(child_node)
                                build_tree_recursive(child_node, callee_name, processed_nodes)
                
                processed_nodes = set()
                build_tree_recursive(call_tree_root, current_func_name, processed_nodes)
                
                # Get pseudocode for selected functions
                for func_info in selected_functions:
                    func_name = func_info["name"]
                    func_addr = func_info["address"]
                    
                    if func_name.lower() in processed_functions:
                        continue
                    
                    pseudocode_container = {"code": ""}
                    
                    def _get_pseudocode_sync():
                        try:
                            from ainalyse.custom_set_cmt import custom_get_pseudocode
                            pseudocode = custom_get_pseudocode(func_addr)
                            if pseudocode:
                                pseudocode_container["code"] = pseudocode
                                return True
                        except Exception as e:
                            print(f"[AETHER] [Realtime] Error getting pseudocode for {func_name}: {e}")
                        return False
                    
                    success = ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
                    
                    if success and pseudocode_container["code"]:
                        pseudocode_store[func_name] = strip_and_reformat_pseudocode_for_realtime(pseudocode_container["code"])
                        processed_functions.add(func_name.lower())

                # Generate context (same for both modes)
                final_tree_str = format_call_tree_ascii(call_tree_root)
                final_pseudocode_listing_str = format_pseudocode_listing_for_realtime(pseudocode_store)
                context = f"CALL TREE:\n{final_tree_str}\n\n{final_pseudocode_listing_str}"
                if smart_select:
                    task = "Smart_Selection"
                    # If smart selection is enabled, filter important functions to send for analysis
                    default_selected = [i["name"] for i in selected_functions]

                    print("[AETHER] [Realtime] Requesting smart select from LLM...")
                    # Call LLM to identify important functions
                    llm_response = call_openai_llm_realtime(
                        f"""
                        You are performing deterministic function classification.

                        Analyze the following set of functions:
                        {default_selected}

                        For EACH function in the set, you MUST follow this decision procedure in order:

                        Step 1: If the function contains meaningful internal logic OR calls at least one IMPORTANT function, label it IMPORTANT.
                        Step 2: Else if the function adds no meaningful logic AND ALL functions it calls are UNIMPORTANT or system functions, label it UNIMPORTANT.
                        Step 3: Else if the function adds no meaningful logic AND calls functions not included or not yet provided, label it WRAPPER.

                        Label precedence is IMPORTANT > UNIMPORTANT > WRAPPER. Only one label is allowed.

                        Reasoning requirements:
                        - Output EXACTLY three sentences per function.
                        - Sentence 1: Describe the function’s internal logic.
                        - Sentence 2: Describe the functions it calls and their classifications.
                        - Sentence 3: Justify the final label using the rules above.
                        - Do NOT use hedging language (e.g., “appears”, “likely”, “possibly”).

                        Output format rules (STRICT):
                        - One function per line.
                        - No extra text, headers, or blank lines.
                        - Use exactly this format:

                        function_name (LABEL) Sentence one. Sentence two. Sentence three.
                        """, context, api_key, model, base_url, system_prompt_at_bottom, prompt_token_warning,
                        extra_body, custom_ca_cert_path, client_cert_path, client_key_path, debug, task
                    )
                    if not llm_response:
                        print("[AETHER] [Realtime] No response from LLM.")
                        return False
                    print(f"\n```Smart Function Analysis\n[AETHER] [Realtime] LLM Response:\n{llm_response}\n```\n")
                    # Keep only important functions
                    smart_selected = []
                    for func in llm_response.split("\n"):
                        try:
                            func_name = func.split(" ")[0]
                            func_label = func.split(" ")[1]
                            smart_selected.append(func_name)
                        except IndexError as e:
                            continue
                        try:
                            if func_label == "(UNIMPORTANT)":
                                pseudocode_store.pop(func_name)
                        except KeyError as e:
                            continue
                    print("Missed functions: "+ str(set(default_selected)-set(smart_selected)))
                    print("Hallucinated functions: "+ str(set(smart_selected)-set(default_selected)))
                    final_pseudocode_listing_str = format_pseudocode_listing_for_realtime(pseudocode_store)
                    context = f"CALL TREE:\n{final_tree_str}\n\n{final_pseudocode_listing_str}"
                    print(f"[AETHER] [Realtime] Collected {len(pseudocode_store)} functions for analysis with Smart Select")

                print("[AETHER] [Realtime] Requesting analysis from LLM...")

                task = "Annotation"
                # Call LLM with the prepared system prompt and context
                llm_response = call_openai_llm_realtime(
                    system_prompt, context, api_key, model, base_url, system_prompt_at_bottom, prompt_token_warning,
                    extra_body, custom_ca_cert_path, client_cert_path, client_key_path, debug, task
                )

                if not llm_response:
                    print("[AETHER] [Realtime] No response from LLM.")
                    return False, None, None, None
                
                print(f"[AETHER] [Realtime] LLM Response:\n{llm_response}")
                
                # Parse response (works for both fast look and correction formats)
                comments, local_variables, function_renames = parse_realtime_response(llm_response)

                # Check settings
                config = load_config()
                use_comments = config.get("USE_DESC", True) or config.get("USE_COMMENTS", True)
                if not use_comments:
                    comments = []
                use_rename_vars = config.get("RENAME_VARS", True)
                if not use_rename_vars:
                    local_variables = []
                use_rename_funcs = config.get("RENAME_FUNCS", True)
                if not use_rename_funcs:
                    function_renames = []
                
                print(f"[AETHER] [Realtime] Parsed {len(comments)} comments, {len(local_variables)} variable renames, {len(function_renames)} function renames")
                
                # Apply changes
                for comment_data in comments:
                    success = await mcp_execute_realtime_action(session, "set_comment", {
                        "address": comment_data["address"],
                        "comment": comment_data["comment"]
                    })
                
                # Get root function address for variable renames
                root_func_addr = current_func_addr
                
                for var_data in local_variables:
                    success = await mcp_execute_realtime_action(session, "rename_local_variable", {
                        "function_address": root_func_addr,
                        "old_name": var_data["old_name"],
                        "new_name": var_data["new_name"]
                    })
                
                for func_data in function_renames:
                    # Find function address by name
                    func_addr_for_rename = None
                    for func_info in selected_functions:
                        if func_info["name"] == func_data["old_name"]:
                            func_addr_for_rename = func_info["address"]
                            break
                    
                    if func_addr_for_rename:
                        new_name = func_data["new_name"]
                        if not func_data["new_name"].startswith("aire_"): new_name = "aire_" + new_name
                        success = await mcp_execute_realtime_action(session, "rename_function", {
                            "function_address": func_addr_for_rename,
                            "new_name": new_name
                        })

                elapsed_time = time.time() - start_time
                print(f"[AETHER] [Realtime] Analysis completed in {elapsed_time:.2f} seconds")

                structured_commands = {
                    "comments": comments,
                    "local_variables": local_variables,
                    "function_renames": function_renames
                }

                refresh_functions(selected_functions, current_func_addr, log_prefix="[AETHER] [Realtime]")
                return True, context, llm_response, structured_commands

    except Exception as e:
        print(f"[AETHER] [Realtime] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None, None

async def run_fast_look_analysis(config: dict, current_func_name: str, current_func_addr: str):
    """Run fast look analysis on current function."""
    print(f"[AETHER] [Fast Look] Starting fast look analysis for function: {current_func_name}")
    return await run_realtime_analysis_common(config, current_func_name, current_func_addr, REALTIME_PROMPT_FILE, False)

async def run_smart_look_analysis(config: dict, current_func_name: str, current_func_addr: str) -> bool:
    """Run smart look analysis on current function."""
    print(f"[AETHER] [Smart Look] Starting fast look analysis for function: {current_func_name}")
    return await run_realtime_analysis_common(config, current_func_name, current_func_addr, REALTIME_PROMPT_FILE, True)

async def run_custom_prompt_analysis(config: dict, current_func_name: str, current_func_addr: str, user_advice: str) -> bool:
    """Run custom prompt correction analysis on current function."""
    print(f"[AETHER] [Custom Re-annotate] Starting custom re-annotation for function: {current_func_name}")
    print(f"[AETHER] [Custom Re-annotate] User advice: {user_advice}")
    
    prompt_replacements = {"INSERT_USER_ADVICE": user_advice}
    return await run_realtime_analysis_common(config, current_func_name, current_func_addr, CORRECTION_PROMPT_FILE, False, prompt_replacements)
