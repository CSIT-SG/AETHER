import time
import datetime
import yara
import re
from urllib.parse import urlparse
import os

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from ainalyse.function_selection import collect_functions_for_generate_report
from ainalyse.manual_gatherer import Node, format_call_tree_ascii
from .realtime import call_openai_llm_realtime, format_call_tree_ascii, strip_and_reformat_pseudocode_for_realtime, format_pseudocode_listing_for_realtime
import ida_kernwin
import idaapi


async def run_generate_report_common(config: dict, current_func_name: str, current_func_addr: str, binary_name: str) -> bool:
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
        print("[AETHER] [Generate Report] Error: MCP_SERVER_URL must start with http:// or https://")
        return False

    if not api_key:
        print("[AETHER] [Generate Report] Error: OPENAI_API_KEY not set in config.")
        return False

    print(f"[AETHER] [Realtime] Using model: {model}")

    # Test MCP connection first before proceeding
    from .. import test_mcp_connection
    print("[AETHER] [Generate Report] Testing MCP connection...")
    mcp_success, mcp_msg = await test_mcp_connection(server_url)
    if not mcp_success:
        print(f"[AETHER] [Generate Report] MCP connection failed: {mcp_msg}")
        return False
    print("[AETHER] [Generate Report] MCP connection test successful")

    
    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [Generate Report] Connected to MCP server.")

                # Use manual gatherer defaults logic to collect functions
                selected_functions_container = {"functions": []}
                
                def _collect_functions_sync():
                    try:
                        result = collect_functions_for_generate_report(
                            current_func_addr, current_func_name, 
                            depth=0, max_depth=5
                        )
                        selected_functions_container["functions"] = result
                        return len(result)
                    except Exception as e:
                        print(f"[AETHER] [Generate Report] Error in function collection: {e}")
                        selected_functions_container["functions"] = []
                        return 0
                
                ida_kernwin.execute_sync(_collect_functions_sync, ida_kernwin.MFF_READ)
                selected_functions = selected_functions_container["functions"]
                print(f"[AETHER] [Generate Report] Collected {len(selected_functions)} functions for analysis")
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
                                print(f"[AETHER] [Generate Report] Error getting callees for {func_name}: {e}")
                        
                        relationships_container["relationships"] = relationships
                        return True
                    except Exception as e:
                        print(f"[AETHER] [Generate Report] Error in call relationship gathering: {e}")
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
                            print(f"[AETHER] [Generate Report] Error getting pseudocode for {func_name}: {e}")
                        return False
                    
                    success = ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
                    
                    if success and pseudocode_container["code"]:
                        pseudocode_store[func_name] = strip_and_reformat_pseudocode_for_realtime(pseudocode_container["code"])
                        processed_functions.add(func_name.lower())

                # Generate context (same for both modes)
                final_tree_str = format_call_tree_ascii(call_tree_root)
                final_pseudocode_listing_str = format_pseudocode_listing_for_realtime(pseudocode_store)
                context = f"CALL TREE:\n{final_tree_str}\n\n{final_pseudocode_listing_str}"
                print("[AETHER] [Generate Report] Requesting analysis from LLM...")
                # Get binary data
                try:
                    with open(binary_name, "rb") as inputfile:
                        binary_data = inputfile.read()
                    print("[AETHER] [Yara] Generating Yara rules to detect binary.")
                except FileNotFoundError:
                    print("[AETHER] [Generate Report] Unable to test Yara rules due to Binary file " + str(binary_name) + " not being found. Make sure binary is in the same folder as current IDA database file.")
                    binary_data = None
                # Try at most 4 times to get yara rules that work
                attempts = 3
                while True:
                    attempts -= 1
                    if attempts < 0:
                        print("[AETHER] [Yara] All Yara rules generated failed to detect the binary. Yara rules in report may not work.")
                        break
                    task = "Report_Generation"
                    # Call LLM with the prepared system prompt and context
                    llm_response = call_openai_llm_realtime(
                        """Title of the report should be """ + os.path.basename(binary_name) + """ Analysis Report. Today's date is """ + str(datetime.date.today()) + """. Generate the following sections if applicable in fixed order for the pseudocode given in md report format: SNORT rules, Behavior Based Detection
                        (First explain overall behavior, then explain all functions with func_ in front or functions with non-standard name. Must contain name of function that causes behavior),
                        Network Traffic, JA3/4, YARA
                        (Code given is pseudo code, so ONLY use strings in quotes for rules. Strings must be at least 10 characters long and uncommon. 
                        Do not use function names, variable names and magic headers for Yara rules. 
                        Regex used to detect strings must be case insensitive.
                        Use regex for strings, and insert .{0,5} between each character of those strings, 
                        and do not convert ascii characters to bytes. At least four strings must be created.
                        String name should be the string itself.
                        Using the same strings, generate 2 Yara rules, one tight and one loose.
                        For loose, condition must be half of the strings. 
                        For tight, condition must be all string.
                        Example Yara Rule: $stringname = /t.{0,5}e.{0,5}s.{0,5}t.{0,5}s.{0,5}t.{0,5}r.{0,5}i.{0,5}n.{0,5}g/i, )
                        IOCs, Execution Flow, Capabilities, Discovered Vulnerability, C2 Infra Identification,
                        C2 Control, Conclusion""", context.replace("aire_", "func_"), api_key, model, base_url, system_prompt_at_bottom,
                        prompt_token_warning, extra_body, custom_ca_cert_path, client_cert_path, client_key_path, debug, task
                    )

                    if not llm_response:
                        print("[AETHER] [Generate Report] No response from LLM.")
                        return False
                    pattern = r"rule [\s\S]*?\n}"
                    match = re.findall(pattern, llm_response)
                    if binary_data:
                        failed = False
                        for i in match:
                            try:
                                rule = yara.compile(source=i)
                                if not rule.match(data=binary_data):
                                    failed = True
                                    break
                            except yara.SyntaxError:
                                failed = True
                                break
                        if failed:
                            if attempts >= 0 :
                                print("[AETHER] [Yara] Yara rules failed to detect the binary. Regenerating Yara rules ("+str(3-attempts)+"/3)...")
                            continue
                        else:
                            print("[AETHER] [Yara] Yara rules succeeded in detecting Binary. Proceeding...")
                            break
                with open(binary_name + "_code_" + current_func_name + ".txt", "w", encoding='utf-8') as outputfile:
                    outputfile.write(context)
                with open(binary_name + "_report_" + current_func_name + ".md", "w", encoding='utf-8') as outputfile:
                    outputfile.write(llm_response.replace("func_", "aire_"))
                elapsed_time = time.time() - start_time
                print(f"[AETHER] [Generate Report] Report generated in {elapsed_time:.2f} seconds")
                return True
                
                
    except Exception as e:
        print(f"[AETHER] [Generate Report] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_generate_report(config: dict, current_func_name: str, current_func_addr: str, binary_name: str) -> bool:
    """Run generate report on current function."""
    print(f"[AETHER] [Generate Report] Starting Generate Report for function: {current_func_name}")
    return await run_generate_report_common(config, current_func_name, current_func_addr, binary_name)
