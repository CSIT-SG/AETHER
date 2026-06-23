import os
from typing import Dict, List
from urllib.parse import urlparse

import ida_kernwin
import idaapi
import idautils
import idc
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

# Import shared utilities - remove the duplicate function
from ..function_selection import collect_functions_with_default_criteria
from .generator_core import stream_and_save_ai_decompilation
from ..preprocessor import format_pseudocode_listing_for_ai_decomp
from .viewer import AI_DECOMP_VIEW_TITLE, g_ai_decomp_viewers, get_function_name_safe

# --- File Paths ---
AI_DECOMP_PROMPT = os.path.join(os.path.dirname(__file__), "..", "prompts/ai-decomp-prompt.txt")
AI_DECOMP_PROMPT_NOTHINK = os.path.join(os.path.dirname(__file__), "..", "prompts/ai-decomp-prompt-nothink.txt")
VERBOSE_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "verbose.txt")

async def run_ai_decomp_for_current_function_b(config: dict, func_addr: str) -> bool:
    """Generate AI decompilation for the current function using Prompt B (variable renaming)."""
    print("[AETHER] [AI Decomp] Running AI decompilation with Prompt B (variable renaming)")
    return await run_ai_decomp_for_current_function(config, func_addr, use_prompt_b=True)

async def run_ai_decomp_for_current_function(config: dict, func_addr: str, use_prompt_b: bool = False) -> bool:
    """Generate AI decompilation for the current function using shared gathering approach."""
    server_url = config["MCP_SERVER_URL"]

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] [AI Decomp] Error: MCP_SERVER_URL must start with http:// or https://")
        return False

    if not config.get("OPENAI_API_KEY"):
        print("[AETHER] [AI Decomp] Error: OPENAI_API_KEY not set in config.")
        return False

    # Set generating state for the viewer (must run on main thread)
    def _set_generating():
        viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
        if viewer_instance:
            viewer_instance.SetGenerating(True)
    ida_kernwin.execute_sync(_set_generating, ida_kernwin.MFF_WRITE)

    try:
        # Load appropriate AI decompilation prompt based on the mode
        prompt_file = AI_DECOMP_PROMPT_NOTHINK if use_prompt_b else AI_DECOMP_PROMPT
        try:
            with open(prompt_file, "r", encoding="utf-8") as f:
                ai_decomp_prompt_template = f.read()
        except FileNotFoundError:
            print(f"[AETHER] [AI Decomp] Error: prompt file not found at {prompt_file}")
            return False
    except Exception as e:
        print(f"[AETHER] [AI Decomp] Error loading prompt: {e}")
        return False

    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [AI Decomp] Connected to MCP server.")

                # Get function name for the current address (using safe method)
                func_name = get_function_name_safe(func_addr)
                
                print(f"[AETHER] [AI Decomp] Starting AI decompilation for function: {func_name} at {func_addr}")
                
                # Use container pattern for reliable data passing from execute_sync
                functions_container = {"selected_functions": []}
                
                def _collect_functions_sync():
                    try:
                        result = collect_functions_with_default_criteria(
                            func_addr, func_name, depth=0, max_depth=5
                        )
                        functions_container["selected_functions"] = result if result else []
                        return len(functions_container["selected_functions"])
                    except Exception as e:
                        print(f"[AETHER] [AI Decomp] Error collecting functions: {e}")
                        functions_container["selected_functions"] = []
                        return 0
                
                ida_kernwin.execute_sync(_collect_functions_sync, ida_kernwin.MFF_READ)
                selected_functions = functions_container["selected_functions"]
                
                if not selected_functions:
                    print("[AETHER] [AI Decomp] Error: No functions collected for analysis")
                    return False
                
                print(f"[AETHER] [AI Decomp] Collected {len(selected_functions)} functions for analysis (using shared default selection logic)")
                print(f"[AETHER] [AI Decomp] Selected functions: {[f['name'] for f in selected_functions]}")

                # Build call tree and pseudocode store
                pseudocode_store = {}
                function_address_map = {}  # Map function names to addresses
                processed_functions = set()  # Track processed functions
                
                # Import classes from manual_gatherer
                from ainalyse.manual_gatherer import Node, format_call_tree_ascii
                
                # Ensure func_name and func_addr are strings when creating Node
                call_tree_root = Node(name=str(func_name), address=str(func_addr))
                
                # Build call relationships
                call_relationships = {}
                
                for func_info in selected_functions:
                    func_name_iter = str(func_info["name"])
                    func_addr_iter = str(func_info["address"])
                    
                    try:
                        func_addr_int = int(func_addr_iter, 16)
                        
                        # Use container pattern for reliable data passing
                        callees_container = {"callees": []}
                        
                        def _get_callees_sync():
                            try:
                                func = idaapi.get_func(func_addr_int)
                                if not func:
                                    callees_container["callees"] = []
                                    return []
                                
                                callees = []
                                callee_functions = set()
                                
                                for instruction_ea in idautils.FuncItems(func.start_ea):
                                    for xref in idautils.XrefsFrom(instruction_ea, 0):
                                        callee_func = idaapi.get_func(xref.to)
                                        if callee_func:
                                            callee_functions.add(callee_func.start_ea)
                                
                                for func_ea in callee_functions:
                                    callee_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                                    if callee_name and any(f["name"] == callee_name for f in selected_functions):
                                        callees.append(callee_name)
                                
                                callees_container["callees"] = callees
                                return len(callees)
                            except Exception as e:
                                print(f"[AETHER] [AI Decomp] Error getting callees for {func_name_iter}: {e}")
                                callees_container["callees"] = []
                                return 0
                        
                        # Get callees on main thread
                        ida_kernwin.execute_sync(_get_callees_sync, ida_kernwin.MFF_READ)
                        
                        # Use the container result
                        callees = callees_container["callees"]
                        if callees:
                            call_relationships[func_name_iter] = callees
                            
                    except Exception as e:
                        print(f"[AETHER] [AI Decomp] Error processing callees for {func_name_iter}: {e}")

                # Build proper hierarchical call tree using call relationships
                def build_call_tree_recursive(parent_node, parent_func_name, processed_nodes):
                    """Recursively build call tree based on actual call relationships."""
                    if parent_func_name in processed_nodes:
                        return  # Avoid infinite loops
                    
                    processed_nodes.add(parent_func_name)
                    
                    # Get callees for this function
                    callees = call_relationships.get(parent_func_name, [])
                    
                    for callee_name in callees:
                        # Find the address for this callee
                        callee_addr = None
                        for func_info in selected_functions:
                            if func_info['name'] == callee_name:
                                callee_addr = func_info['address']
                                break
                        
                        if callee_addr:
                            # Check if this child already exists
                            child_exists = any(child.name == callee_name for child in parent_node.children)
                            if not child_exists:
                                # Create new child node
                                child_node = Node(name=str(callee_name), address=str(callee_addr), parent_name=str(parent_func_name))
                                parent_node.add_child(child_node)
                                
                                # Recursively build tree for this child
                                build_call_tree_recursive(child_node, callee_name, processed_nodes)
                
                # Build the hierarchical tree
                processed_nodes = set()
                build_call_tree_recursive(call_tree_root, func_name, processed_nodes)

                # Get MCP tool helper
                async def mcp_get_tool_text_content(tool_name: str, params=None):
                    try:
                        res = await session.call_tool(tool_name, params if params else {})
                        if res.content and res.content[0] and hasattr(res.content[0], 'text'):
                            return res.content[0].text
                    except Exception as e:
                        print(f"[AETHER] [AI Decomp] Error calling MCP tool {tool_name}: {e}")
                    return None

                # Process selected functions
                valid_functions = []  # Track functions that were successfully processed
                for i, func_info in enumerate(selected_functions):
                    func_name_iter = str(func_info["name"])  # Ensure string
                    func_addr_iter = str(func_info["address"])  # Ensure string
                    
                    # Check for duplicates using case-insensitive comparison
                    if func_name_iter.lower() in processed_functions:
                        print(f"[AETHER] [AI Decomp] Function {func_name_iter} already processed. Skipping duplicate in pseudocode listing.")
                        continue
                    
                    print(f"[AETHER] [AI Decomp] Processing function {i+1}/{len(selected_functions)}: {func_name_iter}")
                    
                    # Store the function name to address mapping
                    function_address_map[func_name_iter] = func_addr_iter
                    
                    # Get pseudocode for this function
                    pseudocode = await mcp_get_tool_text_content("decompile_function", {"address": func_addr_iter})
                    if not pseudocode:
                        print(f"[AETHER] [AI Decomp] Warning: Could not decompile {func_name_iter} at {func_addr_iter}. Skipping.")
                        continue
                    
                    # Store the pseudocode (using the clean version for AI decomp)
                    pseudocode_store[func_name_iter] = pseudocode  # Store raw for internal use
                    processed_functions.add(func_name_iter.lower())  # Add to processed set
                    
                    # Track this as a valid function that will be processed
                    valid_functions.append({
                        'name': func_name_iter,
                        'address': func_addr_iter
                    })

                print(f"[AETHER] [AI Decomp] Processed {len(pseudocode_store)} unique functions for pseudocode listing.")
                
                # Generate the functions list for the prompt
                functions_list_str = ", ".join([f"{func['name']} [{func['address']}]" for func in reversed(valid_functions)])
                
                # Fill in the prompt template
                ai_decomp_prompt = ai_decomp_prompt_template.replace("{FUNCTIONS_LIST}", functions_list_str)

                # Generate context for AI decompilation with error handling
                try:
                    final_tree_str = format_call_tree_ascii(call_tree_root)
                except Exception as e:
                    print(f"[AETHER] [AI Decomp] Error formatting call tree: {e}. Using fallback.")
                    final_tree_str = f"Call tree for {func_name} (formatting error)"
                
                try:
                    # Use the AI decomp specific formatter (no address prefixes) with function addresses
                    final_pseudocode_listing_str = format_pseudocode_listing_for_ai_decomp(pseudocode_store, function_address_map)
                except Exception as e:
                    print(f"[AETHER] [AI Decomp] Error formatting pseudocode listing: {e}. Using fallback.")
                    final_pseudocode_listing_str = "Pseudocode listing (formatting error)"
                
                # Prepare the full prompt
                context = f"CALL TREE:\n{final_tree_str}\n\n{final_pseudocode_listing_str}"
                
                # Call the core generator function with use_prompt_b parameter
                return await stream_and_save_ai_decompilation(config, ai_decomp_prompt, context, functions_list_str, use_prompt_b)

    except Exception as e:
        print(f"[AETHER] [AI Decomp] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        def _error_final():
            viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
            if viewer_instance:
                viewer_instance.SetGenerating(False)
                viewer_instance.UpdateDisplay()
        ida_kernwin.execute_sync(_error_final, ida_kernwin.MFF_WRITE)
        return False

async def run_ai_decomp_for_functions(config: dict, selected_functions: List[Dict[str, str]]) -> bool:
    """Generate AI decompilation for multiple selected functions."""
    server_url = config["MCP_SERVER_URL"]

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] [AI Decomp] Error: MCP_SERVER_URL must start with http:// or https://")
        return False

    if not config.get("OPENAI_API_KEY"):
        print("[AETHER] [AI Decomp] Error: OPENAI_API_KEY not set in config.")
        return False

    try:
        # Load AI decompilation prompt
        with open(AI_DECOMP_PROMPT, "r", encoding="utf-8") as f:
            ai_decomp_prompt_template = f.read()
    except FileNotFoundError:
        print(f"[AETHER] [AI Decomp] Error: ai-decomp-prompt.txt not found at {AI_DECOMP_PROMPT}")
        return False

    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [AI Decomp] Connected to MCP server.")

                # Get root function (first in the list)
                root_function = selected_functions[0]
                root_func_name = root_function["name"]
                root_func_addr = root_function["address"]
                
                print(f"[AETHER] [AI Decomp] Starting AI decompilation for {len(selected_functions)} selected functions, root: {root_func_name}")

                # Build call tree and pseudocode store
                pseudocode_store = {}
                function_address_map = {}  # Map function names to addresses
                
                # Import classes from manual_gatherer
                from ainalyse.manual_gatherer import Node, format_call_tree_ascii
                
                # Build hierarchical call tree from selected functions
                call_tree_root = Node(name=str(root_func_name), address=str(root_func_addr))
                
                # Build call relationships
                call_relationships = {}
                
                for func_info in selected_functions:
                    func_name = func_info["name"]
                    func_addr = func_info["address"]
                    
                    try:
                        func_addr_int = int(func_addr, 16)
                        
                        # Use container pattern for reliable data passing
                        callees_container = {"callees": []}
                        
                        def _get_callees_sync():
                            try:
                                func = idaapi.get_func(func_addr_int)
                                if not func:
                                    callees_container["callees"] = []
                                    return []
                                
                                callees = []
                                callee_functions = set()
                                
                                for instruction_ea in idautils.FuncItems(func.start_ea):
                                    for xref in idautils.XrefsFrom(instruction_ea, 0):
                                        callee_func = idaapi.get_func(xref.to)
                                        if callee_func:
                                            callee_functions.add(callee_func.start_ea)
                                
                                for func_ea in callee_functions:
                                    callee_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                                    if callee_name and any(f["name"] == callee_name for f in selected_functions):
                                        callees.append(callee_name)
                                
                                callees_container["callees"] = callees
                                return len(callees)
                            except Exception as e:
                                print(f"[AETHER] [AI Decomp] Error getting callees for {func_name}: {e}")
                                callees_container["callees"] = []
                                return 0
                        
                        # Get callees on main thread
                        ida_kernwin.execute_sync(_get_callees_sync, ida_kernwin.MFF_READ)
                        
                        # Use the container result
                        callees = callees_container["callees"]
                        if callees:
                            call_relationships[func_name] = callees
                            
                    except Exception as e:
                        print(f"[AETHER] [AI Decomp] Error processing callees for {func_name}: {e}")

                # Build hierarchical tree using call relationships
                def build_tree_recursive(parent_node, parent_func_name, processed_nodes):
                    if parent_func_name in processed_nodes:
                        return
                    
                    processed_nodes.add(parent_func_name)
                    callees = call_relationships.get(parent_func_name, [])
                    
                    if not isinstance(callees, list):
                        callees = []
                    
                    for callee_name in callees:
                        # Find the address for this callee
                        callee_addr = None
                        for func_info in selected_functions:
                            if func_info['name'] == callee_name:
                                callee_addr = func_info['address']
                                break
                        
                        if callee_addr:
                            # Check if child already exists
                            child_exists = any(child.name == callee_name for child in parent_node.children)
                            if not child_exists:
                                child_node = Node(name=callee_name, address=callee_addr, parent_name=parent_func_name)
                                parent_node.add_child(child_node)
                                # Recursively build tree for this child
                                build_tree_recursive(child_node, callee_name, processed_nodes)
                
                # Build the hierarchical tree
                processed_nodes = set()
                build_tree_recursive(call_tree_root, root_func_name, processed_nodes)

                # Get MCP tool helper
                async def mcp_get_tool_text_content(tool_name: str, params=None):
                    try:
                        res = await session.call_tool(tool_name, params if params else {})
                        if res.content and res.content[0] and hasattr(res.content[0], 'text'):
                            return res.content[0].text
                    except Exception as e:
                        print(f"[AETHER] [AI Decomp] Error calling MCP tool {tool_name}: {e}")
                    return None

                # Process all selected functions
                valid_functions = []
                for i, func_info in enumerate(selected_functions):
                    func_name_iter = str(func_info["name"])
                    func_addr_iter = str(func_info["address"])
                    
                    print(f"[AETHER] [AI Decomp] Processing function {i+1}/{len(selected_functions)}: {func_name_iter}")
                    
                    # Store the function name to address mapping
                    function_address_map[func_name_iter] = func_addr_iter
                    
                    # Get pseudocode for this function
                    pseudocode = await mcp_get_tool_text_content("decompile_function", {"address": func_addr_iter})
                    if not pseudocode:
                        print(f"[AETHER] [AI Decomp] Warning: Could not decompile {func_name_iter} at {func_addr_iter}. Skipping.")
                        continue
                    
                    # Store the pseudocode
                    pseudocode_store[func_name_iter] = pseudocode
                    
                    # Track this as a valid function
                    valid_functions.append({
                        'name': func_name_iter,
                        'address': func_addr_iter
                    })

                # Generate the functions list for the prompt
                functions_list_str = ", ".join([f"{func['name']} [{func['address']}]" for func in valid_functions])
                
                # Fill in the prompt template
                ai_decomp_prompt = ai_decomp_prompt_template.replace("{FUNCTIONS_LIST}", functions_list_str)

                # Generate context for AI decompilation
                final_tree_str = format_call_tree_ascii(call_tree_root)
                final_pseudocode_listing_str = format_pseudocode_listing_for_ai_decomp(pseudocode_store, function_address_map)
                
                # Prepare the full prompt
                context = f"CALL TREE:\n{final_tree_str}\n\n{final_pseudocode_listing_str}"
                
                # Call the core generator function
                return await stream_and_save_ai_decompilation(config, ai_decomp_prompt, context, functions_list_str)

    except Exception as e:
        print(f"[AInalyse] [AI Decomp] Unexpected error in multi-function AI decompilation: {e}")
        import traceback
        traceback.print_exc()
        return False
