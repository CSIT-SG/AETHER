import asyncio
import os
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from ainalyse.ssl_helper import create_openai_client_with_custom_ca

# --- File Paths ---
AI_DECOMP_PROMPT = os.path.join(os.path.dirname(__file__), "ai-decomp-prompt.txt")
VERBOSE_LOG_PATH = os.path.join(os.path.dirname(__file__), "verbose.txt")

# --- Netnode Storage for AI Decompilations ---
NETNODE_AI_DECOMP = "$ainalyse.ai_decomp.v1"
AI_DECOMP_VIEW_TITLE = "AI Decompilation"

# --- Global State for Viewers ---
g_ai_decomp_viewers = {}

def get_ai_decomp_netnode():
    """Gets or creates the netnode for storing AI decompilations."""
    nn = idaapi.netnode(NETNODE_AI_DECOMP, 0, True)
    return nn

def save_ai_decomp(func_addr: str, decomp_code: str):
    """Save AI decompilation for a function address."""
    # Use a container to hold the result
    result_container = {"success": False}
    
    def _save_sync():
        nn = get_ai_decomp_netnode()
        try:
            nn.setblob(decomp_code.encode('utf-8'), int(func_addr, 16), 'D')
            print(f"[AETHER] [AI Decomp] [Netnode] Saved AI decompilation to netnode for {func_addr} ({len(decomp_code)} characters)")
            result_container["success"] = True
            return True
        except Exception as e:
            print(f"[AETHER] [AI Decomp] [Netnode] Error saving AI decompilation for {func_addr}: {e}")
            result_container["success"] = False
            return False
    
    # Try execute_sync
    try:
        sync_result = ida_kernwin.execute_sync(_save_sync, ida_kernwin.MFF_WRITE)
        print(f"[AETHER] [AI Decomp] [Netnode] Save execute_sync returned: {sync_result}, container has: {result_container['success']}")
        
        # Use container result if available
        if result_container["success"]:
            return True
        
        # Fallback to sync_result
        return bool(sync_result) if sync_result is not None else False
        
    except Exception as e:
        print(f"[AETHER] [AI Decomp] [Netnode] Save execute_sync failed: {e}")
        # Check container despite exception
        return result_container["success"]

def load_ai_decomp(func_addr: str) -> Optional[str]:
    """Load AI decompilation for a function address."""
    # Use a container to hold the result since execute_sync has issues with return values
    result_container = {"data": None}
    
    def _load_sync():
        nn = get_ai_decomp_netnode()
        try:
            blob = nn.getblob(int(func_addr, 16), 'D')
            if blob:
                result = blob.decode('utf-8')
                result_container["data"] = result
                return result
            else:
                result_container["data"] = None
                return None
        except Exception as e:
            print(f"[AETHER] [AI Decomp] [Netnode] Error loading AI decompilation for {func_addr}: {e}")
            result_container["data"] = None
            return None
    
    # Try execute_sync
    try:
        sync_result = ida_kernwin.execute_sync(_load_sync, ida_kernwin.MFF_READ)
        
        # Use the container result regardless of what execute_sync returns
        if result_container["data"] is not None:
            return result_container["data"]
        
        # If container is empty but sync_result has data, use that
        if isinstance(sync_result, str) and sync_result:
            return sync_result
            
        return None
        
    except Exception as e:
        print(f"[AETHER] [AI Decomp] [Netnode] Execute_sync failed: {e}")
        # Check if we got data in the container despite the exception
        if result_container["data"] is not None:
            return result_container["data"]
        return None

def get_function_name_safe(func_addr_str: str) -> str:
    """Safely get function name from main thread."""
    def _get_name_sync():
        try:
            func_addr_int = int(func_addr_str, 16)
            return ida_funcs.get_func_name(func_addr_int) or f"sub_{func_addr_int:x}"
        except Exception as e:
            print(f"[AETHER] [AI Decomp] Error getting function name for {func_addr_str}: {e}")
            return f"sub_{int(func_addr_str, 16):x}"
    
    # Always use execute_sync
    try:
        result = ida_kernwin.execute_sync(_get_name_sync, ida_kernwin.MFF_READ)
        if isinstance(result, str):
            return result
        return f"sub_{int(func_addr_str, 16):x}"
    except Exception as e:
        print(f"[AETHER] [AI Decomp] Execute_sync function name lookup failed: {e}")
        return f"sub_{int(func_addr_str, 16):x}"

class AIDecompViewer(ida_kernwin.simplecustviewer_t):
    """Custom viewer for AI decompilation display."""
    
    def __init__(self):
        super(AIDecompViewer, self).__init__()
        self.current_func_addr = None
        self.is_generating = False

    def Create(self, title):
        """Creates the custom viewer window."""
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            print("[AETHER] [AI Decomp] Failed to create custom viewer!")
            return False
        g_ai_decomp_viewers[title] = self
        return True

    def SetFunctionAddr(self, func_addr: str):
        """Set the current function address and update display."""
        self.current_func_addr = func_addr
        self.UpdateDisplay()

    def UpdateDisplay(self):
        """Update the display based on current function address."""
        if not self.current_func_addr:
            self.ShowMessage("No function selected")
            return

        # Try multiple attempts to load the data
        existing_decomp = None
        for attempt in range(3):  # Try up to 3 times
            existing_decomp = load_ai_decomp(self.current_func_addr)
            
            if existing_decomp:
                break
            elif attempt < 2:  # Don't sleep on the last attempt
                import time
                time.sleep(0.1)  # Brief pause before retry
        
        if existing_decomp and isinstance(existing_decomp, str) and len(existing_decomp) > 0:
            self.ShowDecompilation(existing_decomp)
        elif self.is_generating:
            self.ShowMessage("Generating AI decompilation, please wait...")
        else:
            self.ShowMessage("No AI decompilation available for this function.\nUse 'Generate AI decompilations' from the context menu to create one.")

    def ShowMessage(self, message: str):
        """Display a message in the viewer."""
        self.ClearLines()
        for line in message.split('\n'):
            colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_DNAME)
            self.AddLine(colored_line)
        self.Refresh()

    def ShowDecompilation(self, decomp_code: str):
        """Display AI decompilation code with proper C++ syntax highlighting."""
        # Safety check to ensure decomp_code is actually a string
        if not isinstance(decomp_code, str):
            decomp_code = str(decomp_code) if decomp_code is not None else "No decompilation data available."
        
        self.ClearLines()
        
        # Add header
        func_name = get_function_name_safe(self.current_func_addr)
        header = f"AI Decompilation for {func_name} [{self.current_func_addr}]"
        header_line = ida_lines.COLSTR(header, ida_lines.SCOLOR_DNAME)
        self.AddLine(header_line)
        self.AddLine("")
        
        # Add decompilation code with enhanced C++ syntax highlighting
        for line in decomp_code.split('\n'):
            line_stripped = line.strip()
            
            if line_stripped.startswith('//'):
                # Comment lines in green
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_AUTOCMT)
            elif line_stripped.startswith('#'):
                # Preprocessor directives in purple
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_MACRO)
            elif any(line_stripped.startswith(keyword) for keyword in [
                'int ', 'void ', 'char ', 'unsigned ', 'signed ', 'long ', 'short ', 'float ', 'double ',
                'bool ', 'struct ', 'union ', 'enum ', 'typedef ', 'const ', 'static ', 'extern ',
                'inline ', 'volatile ', '__int64', '__int32', '__int16', '__int8'
            ]):
                # Type declarations in blue
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_KEYWORD)
            elif any(keyword in line for keyword in [
                'return ', 'if (', 'else', 'for (', 'while (', 'do ', 'switch (', 'case ',
                'break;', 'continue;', 'goto ', 'sizeof(', 'malloc(', 'free(', 'calloc(',
                'realloc(', 'memcpy(', 'memset(', 'strcpy(', 'strcmp(', 'strlen('
            ]):
                # Control flow and standard functions in cyan
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_KEYWORD)
            elif re.search(r'\b0x[0-9a-fA-F]+\b', line):
                # Lines with hex addresses in orange
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_NUMBER)
            elif re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', line) and not line_stripped.startswith('//'):
                # Function calls in light blue
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_IMPNAME)
            elif line_stripped.startswith('{') or line_stripped.startswith('}') or line_stripped == '{' or line_stripped == '}':
                # Braces in white/default but bold
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_SYMBOL)
            elif any(op in line for op in ['++', '--', '+=', '-=', '*=', '/=', '==', '!=', '<=', '>=', '&&', '||', '<<', '>>']):
                # Lines with operators in yellow
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_SYMBOL)
            elif re.search(r'\b\d+\b', line) and not line_stripped.startswith('//'):
                # Lines with numbers in light green
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_NUMBER)
            elif '"' in line and not line_stripped.startswith('//'):
                # String literals in red
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_STRING)
            else:
                # Regular lines - keep default color
                colored_line = line
            
            self.AddLine(colored_line)
        
        self.Refresh()

    def SetGenerating(self, generating: bool):
        """Set the generating state and update display."""
        self.is_generating = generating
        self.UpdateDisplay()

    def OnClose(self):
        """Called when the custom viewer is closed."""
        if AI_DECOMP_VIEW_TITLE in g_ai_decomp_viewers:
            del g_ai_decomp_viewers[AI_DECOMP_VIEW_TITLE]

def show_or_update_ai_decomp_tab(func_addr: str):
    """Show or update the AI decompilation tab for a function."""
    def _show_update_sync():
        try:
            widget = ida_kernwin.find_widget(AI_DECOMP_VIEW_TITLE)

            if widget:
                # Widget exists, update it
                viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
                if viewer_instance:
                    viewer_instance.SetFunctionAddr(func_addr)
                else:
                    print(f"[AETHER] [AI Decomp] [Tab] Widget exists but no viewer instance found in global dict")
            else:
                # Create new widget
                new_viewer = AIDecompViewer()
                if new_viewer.Create(AI_DECOMP_VIEW_TITLE):
                    new_viewer.SetFunctionAddr(func_addr)
                    ida_kernwin.display_widget(new_viewer.GetWidget(), ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WCLS_CLOSE_LATER)
                else:
                    print("[AETHER] [AI Decomp] Failed to create and display the AI decompilation viewer.")
            return True
        except Exception as e:
            print(f"[AETHER] [AI Decomp] Error in _show_update_sync: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # Always use execute_sync
    try:
        ida_kernwin.execute_sync(_show_update_sync, ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"[AETHER] [AI Decomp] Error in show_or_update_ai_decomp_tab: {e}")
        import traceback
        traceback.print_exc()

def parse_ai_decomp_response(response_text: str) -> Dict[str, str]:
    """Parse AI decompilation response and extract function decompilations."""
    decompilations = {}
    
    # Pattern to match function blocks: ```function_name followed by content until ```
    pattern = re.compile(r'```(\w+)\s*\n(.*?)(?:\n```|$)', re.DOTALL)
    
    for match in pattern.finditer(response_text):
        func_name = match.group(1)
        decomp_code = match.group(2).strip()
        
        if decomp_code:
            decompilations[func_name] = decomp_code
            print(f"[AETHER] [AI Decomp] Parsed AI decompilation for function: {func_name}")
    
    return decompilations

def collect_function_callees_safe(func_addr_str: str, func_name: str, current_depth: int, max_depth: int, selected_functions: List[Dict[str, str]]) -> None:
    """Safely collect function callees using IDA API on main thread."""
    def _collect_sync():
        if current_depth >= max_depth or len(selected_functions) >= 15:
            return
        
        try:
            import idautils
            import idc
            
            func_addr_int = int(func_addr_str, 16)
            func = idaapi.get_func(func_addr_int)
            if not func:
                return
            
            callee_functions = set()
            for instruction_ea in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(instruction_ea, 0):
                    callee_func = idaapi.get_func(xref.to)
                    if callee_func:
                        callee_functions.add(callee_func.start_ea)
            
            for func_ea in sorted(list(callee_functions)):
                if len(selected_functions) >= 15:
                    break
                    
                callee_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                if callee_name:
                    # Apply default selection logic (main or sub_* functions)
                    if callee_name == "main" or callee_name.startswith("sub_"):
                        # Check if not already added
                        if not any(f['name'] == callee_name for f in selected_functions):
                            callee_addr = hex(func_ea)
                            selected_functions.append({
                                'name': str(callee_name),  # Ensure name is string
                                'address': str(callee_addr)  # Ensure address is string
                            })
                            print(f"[AETHER] [AI Decomp] Auto-selected function: {callee_name}")
                            
                            # Recursively collect callees
                            collect_function_callees_safe(callee_addr, callee_name, current_depth + 1, max_depth, selected_functions)
        except Exception as e:
            print(f"[AETHER] [AI Decomp] Error collecting callees for {func_name}: {e}")
    
    # Execute on main thread
    ida_kernwin.execute_sync(_collect_sync, ida_kernwin.MFF_READ)

def strip_and_reformat_pseudocode_for_ai_decomp(pseudocode: str) -> str:
    """
    Clean pseudocode for AI decompilation by removing address prefixes and comments,
    returning only the clean code without cannotComment; or 0x prefix lines.
    """
    import re
    lines = pseudocode.splitlines()
    result = []
    line_re = re.compile(r'^\s*/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*/\s*(.*)$')
    
    for line in lines:
        # Skip lines that have our internal formatting prefixes
        if line.strip().startswith('cannotComment;'):
            # Extract just the code part after cannotComment;
            clean_line = line.split('cannotComment;', 1)[1].strip()
            if clean_line:
                result.append(clean_line)
            continue
        elif re.match(r'^\s*0x[0-9a-fA-F]+;', line):
            # Extract just the code part after address;
            clean_line = re.sub(r'^\s*0x[0-9a-fA-F]+;\s*', '', line)
            if clean_line:
                result.append(clean_line)
            continue
            
        m = line_re.match(line)
        if m:
            code = m.group(3)
            if code:
                result.append(code)
        else:
            # Regular line without our special formatting
            if line.strip():
                result.append(line)
            else:
                result.append("")  # Preserve empty lines
    
    return "\n".join(result)

def format_pseudocode_listing_for_ai_decomp(pseudocode_store: Dict[str, str], function_address_map: Dict[str, str]) -> str:
    """Format pseudocode listing for AI decompilation without address prefixes, but include function addresses in headers."""
    if not pseudocode_store:
        return "FUNCTIONS PSEUDOCODE:\n\nNo pseudocode collected yet."
    listing = "FUNCTIONS PSEUDOCODE:\n"
    for func_name, code in pseudocode_store.items():
        # Use the clean formatting for AI decompilation
        formatted_code = strip_and_reformat_pseudocode_for_ai_decomp(code)
        # Get the function address for this function
        func_addr = function_address_map.get(func_name, "unknown")
        listing += f"\n=====\n{func_name}(...) [{func_addr}]\n=====\n\n{formatted_code.strip()}\n"
    return listing

def parse_ai_decomp_response_by_address(response_text: str) -> Dict[str, str]:
    """Parse AI decompilation response and extract function decompilations by address."""
    decompilations = {}
    
    # Pattern to match function blocks: ```0xADDRESS followed by content until ``` or end
    # The address format should be: ```0xHEXADDRESS (with or without newline after)
    pattern = re.compile(r'```(0x[0-9a-fA-F]+)\s*\n(.*?)(?:\n```|$)', re.DOTALL)
    
    for match in pattern.finditer(response_text):
        func_addr = match.group(1)  # The address like 0xa121ae
        decomp_code = match.group(2).strip()
        
        if decomp_code and func_addr:
            # Always overwrite - this handles chunking where we get partial then complete functions
            decompilations[func_addr] = decomp_code
    
    return decompilations

def check_and_save_new_decompilations(decompilations: Dict[str, str], already_saved: set) -> None:
    """Check for new decompilations and save them to netnode if not already saved."""
    for func_addr, decomp_code in decompilations.items():
        # Check if we should save/update this function
        should_save = False
        
        if func_addr not in already_saved:
            # First time seeing this function
            should_save = True
            already_saved.add(func_addr)
            print(f"[AETHER] [AI Decomp] [Real-time] Found new AI decompilation for {func_addr}")
        else:
            # Function exists, check if content has grown significantly (chunking update)
            existing_decomp = load_ai_decomp(func_addr)
            if existing_decomp and len(decomp_code) > len(existing_decomp) + 50:  # Significant growth
                should_save = True
                print(f"[AETHER] [AI Decomp] [Real-time] Updated AI decompilation for {func_addr} ({len(existing_decomp)} -> {len(decomp_code)} chars)")
            elif not existing_decomp:
                # No existing decompilation found (maybe previous save failed), save this one
                should_save = True
                print(f"[AETHER] [AI Decomp] [Real-time] Retrying save for {func_addr} (no existing data found)")
        
        if should_save:
            # Save to netnode
            save_success = save_ai_decomp(func_addr, decomp_code)
            if save_success:
                print(f"[AETHER] [AI Decomp] [Real-time] Successfully saved AI decompilation for {func_addr}")
                
                # Update viewer if it's showing this function
                def _update_viewer_for_addr():
                    viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
                    if (viewer_instance and 
                        viewer_instance.current_func_addr and
                        viewer_instance.current_func_addr.lower() == func_addr.lower()):
                        viewer_instance.SetGenerating(False)
                        viewer_instance.UpdateDisplay()
                try:
                    ida_kernwin.execute_sync(_update_viewer_for_addr, ida_kernwin.MFF_WRITE)
                except Exception as e:
                    print(f"[AETHER] [AI Decomp] [Real-time] Error updating viewer: {e}")
            else:
                print(f"[AETHER] [AI Decomp] [Real-time] Failed to save AI decompilation for {func_addr}")

async def run_ai_decomp_for_current_function(config: dict, func_addr: str) -> bool:
    """Generate AI decompilation for the current function using manual gatherer approach."""
    api_key = config["OPENAI_API_KEY"]
    model = config["OPENAI_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    server_url = config["MCP_SERVER_URL"]
    extra_body = config.get("OPENAI_EXTRA_BODY", {})
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] [AI Decomp] Error: MCP_SERVER_URL must start with http:// or https://")
        return False

    if not api_key:
        print("[AETHER] [AI Decomp] Error: OPENAI_API_KEY not set in config.")
        return False

    # Set generating state for the viewer (must run on main thread)
    def _set_generating():
        viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
        if viewer_instance:
            viewer_instance.SetGenerating(True)
    ida_kernwin.execute_sync(_set_generating, ida_kernwin.MFF_WRITE)

    try:
        # Load AI decompilation prompt
        with open(AI_DECOMP_PROMPT, "r", encoding="utf-8") as f:
            ai_decomp_prompt = f.read()
    except FileNotFoundError:
        print(f"[AETHER] [AI Decomp] Error: ai-decomp-prompt.txt not found at {AI_DECOMP_PROMPT}")
        return False

    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [AI Decomp] Connected to MCP server.")

                # Get function name for the current address (using safe method)
                func_name = get_function_name_safe(func_addr)
                
                print(f"[AETHER] [AI Decomp] Starting AI decompilation for function: {func_name} at {func_addr}")
                
                # Collect functions using safe method (5 levels deep with default selection)
                selected_functions = []
                
                # Add the root function
                selected_functions.append({
                    'name': str(func_name),
                    'address': str(func_addr)
                })
                
                # Collect callees up to 5 levels deep (run on main thread)
                collect_function_callees_safe(func_addr, func_name, 0, 5, selected_functions)
                
                print(f"[AETHER] [AI Decomp] Collected {len(selected_functions)} functions for analysis")

                # Build call tree and pseudocode store
                pseudocode_store = {}
                function_address_map = {}  # Map function names to addresses
                
                # Import classes from manual_gatherer
                from ainalyse.manual_gatherer import Node, format_call_tree_ascii
                
                # Ensure func_name and func_addr are strings when creating Node
                call_tree_root = Node(name=str(func_name), address=str(func_addr))
                
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
                for i, func_info in enumerate(selected_functions):
                    func_name_iter = str(func_info["name"])  # Ensure string
                    func_addr_iter = str(func_info["address"])  # Ensure string
                    
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
                    
                    # Add to call tree (simplified - treat all non-root functions as children of root)
                    if func_name_iter != str(func_name):
                        parent_node = call_tree_root.find_node(str(func_name))
                        if parent_node:
                            child_exists = any(child.name == func_name_iter for child in parent_node.children)
                            if not child_exists:
                                # Ensure all parameters are strings when creating Node
                                new_node = Node(name=str(func_name_iter), address=str(func_addr_iter), parent_name=str(func_name))
                                parent_node.add_child(new_node)
                    
                    await asyncio.sleep(0.05)  # Brief delay

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
                
                # Log verbose
                try:
                    with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                        vf.write("\n--- AI Decompilation Prompt ---\n")
                        vf.write(ai_decomp_prompt)
                        vf.write("\n--- AI Decompilation Context ---\n")
                        vf.write(context)
                        vf.write("\n--- END AI Decompilation Input ---\n")
                except Exception as e:
                    print(f"[AETHER] [AI Decomp] Error writing to verbose.txt: {e}")

                print("[AETHER] [AI Decomp] Requesting AI decompilation from LLM...")
                
                # Stream response from LLM with improved real-time processing
                try:
                    client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path)
                    
                    request_params = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": ai_decomp_prompt},
                            {"role": "user", "content": context}
                        ],
                        "max_tokens": 8192,
                        "temperature": 0.7,
                        "stream": True
                    }
                    
                    if extra_body:
                        request_params["extra_body"] = extra_body
                    
                    stream = client.chat.completions.create(**request_params)
                    
                    full_response = ""
                    already_saved = set()  # Track which function addresses we've already saved
                    
                    print("[AETHER] [AI Decomp] Streaming AI decompilation response...")
                    
                    for chunk in stream:
                        content = getattr(chunk.choices[0].delta, "content", None)
                        if content is None:
                            continue
                            
                        # Accumulate the response
                        full_response += content
                        
                        # Parse the complete response so far for any complete function blocks
                        current_decompilations = parse_ai_decomp_response_by_address(full_response)
                        
                        # Check for new decompilations and save them immediately
                        check_and_save_new_decompilations(current_decompilations, already_saved)

                    print(f"\n[AETHER] [AI Decomp] Streaming completed. Response length: {len(full_response)} characters")
                    
                    # Final parse to ensure we got everything and save the latest versions
                    final_decompilations = parse_ai_decomp_response_by_address(full_response)
                    
                    # Force save all final decompilations to ensure we have the latest complete versions
                    print(f"[AETHER] [AI Decomp] Final processing: Ensuring all {len(final_decompilations)} functions are saved with latest content")
                    for func_addr_final, decomp_code_final in final_decompilations.items():
                        save_success = save_ai_decomp(func_addr_final, decomp_code_final)
                        if save_success:
                            print(f"[AETHER] [AI Decomp] Final save: Successfully saved complete AI decompilation for {func_addr_final} ({len(decomp_code_final)} chars)")
                        else:
                            print(f"[AETHER] [AI Decomp] Final save: Failed to save AI decompilation for {func_addr_final}")
                    
                    # Log the full response
                    try:
                        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                            vf.write("\n--- AI Decompilation LLM Response ---\n")
                            vf.write(full_response)
                            vf.write("\n--- END AI Decompilation Response ---\n")
                            vf.write(f"\n--- AI Decompilation Summary ---\n")
                            vf.write(f"Total functions processed: {len(final_decompilations)}\n")
                            vf.write(f"Function addresses: {list(final_decompilations.keys())}\n")
                            vf.write("--- END AI Decompilation Summary ---\n")
                    except Exception as e:
                        print(f"[AETHER] [AI Decomp] Error writing LLM response to verbose.txt: {e}")

                    print(f"[AETHER] [AI Decomp] AI decompilation completed successfully. Processed {len(final_decompilations)} functions.")
                    
                    # Update viewer state (must run on main thread)
                    def _final_update():
                        viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
                        if viewer_instance:
                            viewer_instance.SetGenerating(False)
                            viewer_instance.UpdateDisplay()
                    ida_kernwin.execute_sync(_final_update, ida_kernwin.MFF_WRITE)
                    
                    return True

                except Exception as e:
                    print(f"[AETHER] [AI Decomp] Error during streaming: {e}")
                    def _error_update():
                        viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
                        if viewer_instance:
                            viewer_instance.SetGenerating(False)
                            viewer_instance.UpdateDisplay()
                    ida_kernwin.execute_sync(_error_update, ida_kernwin.MFF_WRITE)
                    return False

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

# --- Hexrays Hook for Auto-updating the Tab ---
class AIDecompHexraysHooks(ida_hexrays.Hexrays_Hooks):
    """Hooks into Hex-Rays events to detect when the user changes functions."""
    
    def switch_pseudocode(self, vdui):
        """Called when a pseudocode view is open or the user switches functions."""
        func_ea = vdui.cfunc.entry_ea
        func_addr = hex(func_ea)

        # Only update if our AI decomp viewer tab actually exists
        if AI_DECOMP_VIEW_TITLE in g_ai_decomp_viewers:
            show_or_update_ai_decomp_tab(func_addr)
        return 0

# --- Global hooks instance ---
_ai_decomp_hooks = None

def install_ai_decomp_hooks():
    """Install the Hexrays hooks for AI decompilation."""
    global _ai_decomp_hooks
    if not _ai_decomp_hooks and ida_hexrays.init_hexrays_plugin():
        _ai_decomp_hooks = AIDecompHexraysHooks()
        _ai_decomp_hooks.hook()
        print("[AETHER] [AI Decomp] Installed Hexrays hooks for auto-updating.")

def remove_ai_decomp_hooks():
    """Remove the Hexrays hooks for AI decompilation."""
    global _ai_decomp_hooks
    if _ai_decomp_hooks:
        _ai_decomp_hooks.unhook()
        _ai_decomp_hooks = None
        print("[AETHER] [AI Decomp] Removed Hexrays hooks.")
