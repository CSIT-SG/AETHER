import os
import re
import traceback
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

import ida_kernwin
import idaapi
import idautils
import idc
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

# -- Internal Imports --
from .custom_set_cmt import custom_get_pseudocode

# --- File Paths ---
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

# --- Manual Gatherer Logic ---
class Node:
    def __init__(self, name: str, address: Optional[str] = None, parent_name: Optional[str] = None):
        # Ensure all parameters are strings
        self.name = str(name) if name is not None else "unknown"
        self.address = str(address) if address is not None else None
        self.parent_name = str(parent_name) if parent_name is not None else None
        self.children: List["Node"] = []

    def add_child(self, child_node: "Node"):
        self.children.append(child_node)

    def find_node(self, name: str) -> Optional["Node"]:
        # Ensure comparison with string
        search_name = str(name) if name is not None else "unknown"
        if self.name == search_name:
            return self
        for child in self.children:
            found = child.find_node(search_name)
            if found:
                return found
        return None

def _generate_tree_lines_recursive(node: Node, prefix: str, is_last_child: bool) -> List[str]:
    connector = "└── " if is_last_child else "├── "
    # Ensure node.name is a string
    node_name = str(node.name) if node.name is not None else "unknown"
    node_address = str(node.address) if node.address is not None else ""
    line = prefix + connector + node_name + (f" [{node_address}]" if node_address else "")
    lines = [line]
    children_count = len(node.children)
    for i, child in enumerate(node.children):
        extension = "    " if is_last_child else "│   "
        lines.extend(_generate_tree_lines_recursive(child, prefix + extension, i == children_count - 1))
    return lines

def format_call_tree_ascii(root_node: Optional[Node]) -> str:
    if not root_node:
        return "No call tree available."
    
    # Ensure root_node.name and address are strings
    root_name = str(root_node.name) if root_node.name is not None else "unknown"
    root_address = str(root_node.address) if root_node.address is not None else ""
    
    lines = [root_name + (f" [{root_address}]" if root_address else "")]
    children_count = len(root_node.children)
    for i, child in enumerate(root_node.children):
        lines.extend(_generate_tree_lines_recursive(child, "", i == children_count - 1))
    return "\n".join(lines)

def strip_and_reformat_pseudocode(pseudocode: str) -> str:
    """
    Simply return clean pseudocode with address prefixes for lines that have addresses,
    and 'cannotComment' for lines without addresses.
    """
    lines = pseudocode.splitlines()
    result = []
    line_re = re.compile(r'^\s*/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*/\s*(.*)$')
    
    for line in lines:
        # Skip lines that already have our formatting
        if line.strip().startswith('cannotComment|') or re.match(r'^\s*0x[0-9a-fA-F]+\|', line):
            result.append(line)
            continue
            
        m = line_re.match(line)
        if m:
            address = m.group(2)  # May be None
            code = m.group(3)
            if address:
                result.append(f"{address}| {code}")
            else:
                result.append(f"cannotComment| {code}")
        else:
            # Line without our special comment format, treat as cannotComment
            # But only if it's not empty or just whitespace
            if line.strip():
                result.append(f"cannotComment| {line}")
            else:
                result.append(line)  # Preserve empty lines as-is
    return "\n".join(result)

def format_pseudocode_listing(pseudocode_store: Dict[str, str]) -> str:
    if not pseudocode_store:
        return "FUNCTIONS PSEUDOCODE:\n\nNo pseudocode collected yet."
    listing = "FUNCTIONS PSEUDOCODE:\n"
    for func_name, code in pseudocode_store.items():
        formatted_code = strip_and_reformat_pseudocode(code)
        listing += f"\n=====\n{func_name}(...)\n=====\n\n{formatted_code.strip()}\n"
    return listing

async def mcp_get_tool_text_content(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> Optional[str]:
    try:
        res = await session.call_tool(tool_name, params if params else {})
        if res.content and res.content[0] and hasattr(res.content[0], 'text'):
            return res.content[0].text
    except Exception as e:
        print(f"[AETHER] [Manual Gatherer] Error calling MCP tool {tool_name}: {e}")
    return None

async def run_manual_gatherer_agent(config: dict):
    """Manual gatherer that processes user-selected functions without LLM."""
    _init_paths()  # Initialize file paths lazily to avoid circular imports
    
    server_url = config["MCP_SERVER_URL"]
    manual_functions = config.get("manual_functions", [])

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] Error: MCP_SERVER_URL must start with http:// or https://")
        return False, None, None

    if not manual_functions:
        print("[AETHER] Error: No manual functions provided.")
        return False, None, None

    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AETHER] [Manual Gatherer] Connected to MCP server.")

                # Get IDB metadata
                idb_metadata_raw = await mcp_get_tool_text_content(session, "get_metadata")
                idb_metadata = idb_metadata_raw if idb_metadata_raw else "Not available."
                print(f"[AETHER] [Manual Gatherer] Retrieved IDB metadata: {idb_metadata[:300]}...")

                # Find the root function (first in the list)
                root_function = manual_functions[0]
                root_func_name = root_function["name"]
                root_func_addr = root_function["address"]
                
                print(f"[AETHER] [Manual Gatherer] Starting manual analysis with root function: {root_func_name} at {root_func_addr}")
                print(f"[AETHER] [Manual Gatherer] Processing {len(manual_functions)} selected functions...")

                # Initialize data structures
                pseudocode_store: Dict[str, str] = {}
                processed_functions = set()  # Track functions we've already processed
                call_tree_root: Node = Node(name=root_func_name, address=root_func_addr)
                
                # Build proper hierarchical tree based on actual call relationships
                # First, get all call relationships using IDA API directly
                call_relationships = {}
                
                # Container for all call relationships - must be populated from main thread
                relationships_container = {"relationships": {}}
                
                def _get_all_call_relationships_sync():
                    try:
                        relationships = {}
                        
                        for func_info in manual_functions:
                            func_name = func_info["name"]
                            func_addr = func_info["address"]
                            
                            try:
                                func_addr_int = int(func_addr, 16)
                                func = idaapi.get_func(func_addr_int)
                                if not func:
                                    continue
                                
                                callees = []
                                callee_functions = set()
                                
                                for instruction_ea in idautils.FuncItems(func.start_ea):
                                    for xref in idautils.XrefsFrom(instruction_ea, 0):
                                        callee_func = idaapi.get_func(xref.to)
                                        if callee_func:
                                            callee_functions.add(callee_func.start_ea)
                                
                                for func_ea in callee_functions:
                                    callee_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                                    if callee_name and any(f["name"] == callee_name for f in manual_functions):
                                        callees.append(callee_name)
                                
                                if callees:
                                    relationships[func_name] = callees
                                    
                            except Exception as e:
                                print(f"[AETHER] [Manual Gatherer] Error getting callees for {func_name}: {e}")
                        
                        relationships_container["relationships"] = relationships
                        return True
                        
                    except Exception as e:
                        print(f"[AETHER] [Manual Gatherer] Error in call relationship gathering: {e}")
                        relationships_container["relationships"] = {}
                        return False
                
                # Get all call relationships on main thread
                ida_kernwin.execute_sync(_get_all_call_relationships_sync, ida_kernwin.MFF_READ)
                call_relationships = relationships_container["relationships"]
                
                print(f"[AETHER] [Manual Gatherer] Built call relationships: {call_relationships}")

                # Build hierarchical tree using call relationships
                def build_tree_recursive(parent_node, parent_func_name, processed_nodes):
                    if parent_func_name in processed_nodes:
                        return
                    
                    processed_nodes.add(parent_func_name)
                    callees = call_relationships.get(parent_func_name, [])
                    
                    # Ensure callees is always a list
                    if not isinstance(callees, list):
                        print(f"[AETHER] [Manual Gatherer] Warning: callees for {parent_func_name} is not a list, got {type(callees)}: {callees}")
                        callees = []
                    
                    for callee_name in callees:
                        # Find the address for this callee
                        callee_addr = None
                        for func_info in manual_functions:
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
                
                # Process all selected functions for pseudocode
                for i, func_info in enumerate(manual_functions):
                    func_name = func_info["name"]
                    func_addr = func_info["address"]
                    
                    # Check for duplicates using case-insensitive comparison
                    if func_name.lower() in processed_functions:
                        print(f"[AETHER] [Manual Gatherer] Function {func_name} already processed. Skipping duplicate in pseudocode listing.")
                        continue
                        
                    print(f"[AETHER] [Manual Gatherer] Processing function {i+1}/{len(manual_functions)}: {func_name}")
                    
                    # Get pseudocode for this function using custom implementation
                    pseudocode_container = {"code": ""}
                    
                    def _get_pseudocode_sync():
                        try:
                            pseudocode = custom_get_pseudocode(func_addr)
                            if pseudocode:
                                pseudocode_container["code"] = pseudocode
                                return True
                        except Exception as e:
                            print(f"[AETHER] [Manual Gatherer] Error getting pseudocode for {func_name}: {e}")
                        return False
                    
                    success = ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
                    
                    if not success or not pseudocode_container["code"]:
                        print(f"[AETHER] [Manual Gatherer] Warning: Could not decompile {func_name} at {func_addr}. Skipping.")
                        continue
                    
                    # Store the pseudocode
                    pseudocode_store[func_name] = strip_and_reformat_pseudocode(pseudocode_container["code"])
                    processed_functions.add(func_name.lower())  # Add to processed set

                print(f"[AETHER] [Manual Gatherer] Processed {len(pseudocode_store)} unique functions for pseudocode listing.")
                
                # Generate final output
                final_tree_str = format_call_tree_ascii(call_tree_root)
                final_pseudocode_listing_str = format_pseudocode_listing(pseudocode_store)
                
                print(f"[AETHER] [Manual Gatherer] Final call tree:\n{final_tree_str}")
                
                # Write output files
                try:
                    with open(CTX_FILE_PATH, "w", encoding="utf-8") as f:
                        f.write("FINAL CALL TREE:\n")
                        f.write(final_tree_str)
                        f.write("\n\nFINAL PSEUDOCODE LISTING:\n")
                        f.write(final_pseudocode_listing_str)
                    
                    # Log to verbose file
                    with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                        vf.write("\n--- Manual Gatherer Session ---\n")
                        vf.write(f"Root Function: {root_func_name} at {root_func_addr}\n")
                        vf.write(f"Selected Functions: {[f['name'] for f in manual_functions]}\n")
                        vf.write("Final Call Tree:\n")
                        vf.write(final_tree_str)
                        vf.write("\n--- END Manual Gatherer Session ---\n")
                        
                except Exception as e:
                    print(f"[AETHER] [Manual Gatherer] Error writing output files: {e}")
                    return False, None, None
                
                print(f"[AETHER] [Manual Gatherer] Manual gathering complete. Processed {len(pseudocode_store)} functions.")
                
                # Create a simple gathered output summary for history
                gathered_output = f"Manual Gatherer Session\nRoot Function: {root_func_name}\nProcessed Functions: {', '.join(pseudocode_store.keys())}\nTotal Functions: {len(pseudocode_store)}"
                
                return True, root_func_name, gathered_output
                
    except Exception as e:
        print(f"[AETHER] [Manual Gatherer] Unexpected error: {e}")
        traceback.print_exc()
    
    return False, None, None
