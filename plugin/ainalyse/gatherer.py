import asyncio
import json
import os
import re
import traceback
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import ida_kernwin
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from PyQt5 import QtCore, QtWidgets

from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from ainalyse.utils import check_and_add_intranet_headers

from .custom_set_cmt import custom_get_pseudocode

# --- File Paths ---
PROMPT_GATHERER = os.path.join(os.path.dirname(__file__), "prompts/gatherer-prompt.txt")

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

# --- Gatherer Logic ---
class Node:
    def __init__(self, name: str, address: Optional[str] = None, parent_name: Optional[str] = None):
        self.name = name
        self.address = address
        self.parent_name = parent_name
        self.children: List["Node"] = []

    def add_child(self, child_node: "Node"):
        self.children.append(child_node)

    def find_node(self, name: str) -> Optional["Node"]:
        if self.name == name:
            return self
        for child in self.children:
            found = child.find_node(name)
            if found:
                return found
        return None

def _generate_tree_lines_recursive(node: Node, prefix: str, is_last_child: bool) -> List[str]:
    connector = "└── " if is_last_child else "├── "
    line = prefix + connector + node.name + (f" [{node.address}]" if node.address else "")
    lines = [line]
    children_count = len(node.children)
    for i, child in enumerate(node.children):
        extension = "    " if is_last_child else "│   "
        lines.extend(_generate_tree_lines_recursive(child, prefix + extension, i == children_count - 1))
    return lines

def format_call_tree_ascii(root_node: Optional[Node]) -> str:
    if not root_node:
        return "No call tree available."
    lines = [root_node.name + (f" [{root_node.address}]" if root_node.address else "")]
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

def call_openai_llm_gatherer(prompt_content: str, api_key: str, model: str, base_url: str, extra_body: dict = None, custom_ca_cert_path: str = "", client_cert_path: str = "", client_key_path: str = "") -> str:
    try:
        feature = "gatherer"
        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path, feature)
        
        # Append "/no_think" to the user message for gatherer
        user_message_content = prompt_content + "/no_think"
        
        # Prepare request parameters
        request_params = {
            "model": model,
            "messages": [{"role": "user", "content": user_message_content}],
            "max_tokens": 8192,
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
        print(f"[AETHER] Error calling OpenAI API (gatherer): {e}")
        return ""

def parse_llm_response(response_text: str) -> Tuple[List[Dict[str, str]], bool]:
    commands = []
    done_triggered = "DONE_1839ae" in response_text
    add_functions_match = re.search(r"```addFunctions\s*\n(.*?)\n\s*```", response_text, re.DOTALL | re.IGNORECASE)
    if add_functions_match:
        functions_block = add_functions_match.group(1).strip()
        if functions_block:
            lines = functions_block.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                parts = [part.strip() for part in line.split(',')]
                if len(parts) == 2 and parts[0] and parts[1]:
                    commands.append({"type": "add", "name": parts[0], "source": parts[1]})
    return commands, done_triggered

async def mcp_get_tool_json_content(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> Optional[Dict]:
    try:
        res = await session.call_tool(tool_name, params if params else {})
        if res.content and res.content[0] and res.content[0].text:
            return json.loads(res.content[0].text)
    except Exception as e:
        print(f"[AETHER] Error calling MCP tool {tool_name}: {e}")
    return None

async def mcp_get_tool_text_content(session: ClientSession, tool_name: str, params: Optional[Dict] = None) -> Optional[str]:
    try:
        res = await session.call_tool(tool_name, params if params else {})
        if res.content and res.content[0] and hasattr(res.content[0], 'text'):
            return res.content[0].text
    except Exception as e:
        print(f"[AETHER] Error calling MCP tool {tool_name}: {e}")
    return None

class GatheringResultsDialog(QtWidgets.QDialog):
    """Dialog to show gathering results and allow user to continue or retry."""
    
    def __init__(self, call_tree_str, pseudocode_store, parent=None):
        super(GatheringResultsDialog, self).__init__()
        self.setWindowTitle("Gathering Complete - Review Results")
        self.setMinimumSize(700, 500)
        self.call_tree_str = call_tree_str
        self.pseudocode_store = pseudocode_store
        self.user_choice = "continue"  # Default choice
        
        layout = QtWidgets.QVBoxLayout()
        
        # Header
        header_label = QtWidgets.QLabel("LLM Gatherer has completed. Review the results and choose your next action:")
        header_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        # Summary info
        summary_text = f"Functions gathered: {len(pseudocode_store)}\n"
        summary_text += f"Functions: {', '.join(pseudocode_store.keys())}"
        summary_label = QtWidgets.QLabel(summary_text)
        summary_label.setWordWrap(True)
        summary_label.setStyleSheet("background-color: #f0f0f0; padding: 10px; border: 1px solid #ccc; margin-bottom: 10px;")
        layout.addWidget(summary_label)
        
        # Tabs for call tree and function list
        tab_widget = QtWidgets.QTabWidget()
        
        # Call tree tab
        tree_tab = QtWidgets.QWidget()
        tree_layout = QtWidgets.QVBoxLayout()
        tree_text = QtWidgets.QTextEdit()
        tree_text.setPlainText(call_tree_str)
        tree_text.setReadOnly(True)
        tree_text.setFont(QtWidgets.QApplication.font())  # Use monospace for better tree display
        tree_layout.addWidget(tree_text)
        tree_tab.setLayout(tree_layout)
        tab_widget.addTab(tree_tab, "Call Tree")
        
        # Functions list tab
        functions_tab = QtWidgets.QWidget()
        functions_layout = QtWidgets.QVBoxLayout()
        
        functions_list = QtWidgets.QListWidget()
        for func_name in pseudocode_store.keys():
            functions_list.addItem(func_name)
        functions_layout.addWidget(functions_list)
        functions_tab.setLayout(functions_layout)
        tab_widget.addTab(functions_tab, f"Functions ({len(pseudocode_store)})")
        
        layout.addWidget(tab_widget)
        
        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        
        self.retry_button = QtWidgets.QPushButton("Retry Gathering")
        self.retry_button.setToolTip("Start gathering process again with the same initial function")
        self.retry_button.clicked.connect(self.retry_gathering)
        button_layout.addWidget(self.retry_button)
        
        self.cancel_button = QtWidgets.QPushButton("Cancel Analysis")
        self.cancel_button.setToolTip("Cancel the entire analysis process")
        self.cancel_button.clicked.connect(self.cancel_analysis)
        button_layout.addWidget(self.cancel_button)
        
        button_layout.addStretch()
        
        self.continue_button = QtWidgets.QPushButton("Continue to Annotator")
        self.continue_button.setToolTip("Proceed with these gathered functions to the annotation phase")
        self.continue_button.setDefault(True)  # Make this the default button
        self.continue_button.clicked.connect(self.continue_to_annotator)
        button_layout.addWidget(self.continue_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def continue_to_annotator(self):
        self.user_choice = "continue"
        self.accept()
    
    def retry_gathering(self):
        self.user_choice = "retry"
        self.accept()
    
    def cancel_analysis(self):
        self.user_choice = "cancel"
        self.reject()  # Use reject() for cancel to distinguish from accept()
    
    def get_user_choice(self):
        return self.user_choice

async def run_gatherer_agent(config: dict):
    _init_paths()  # Initialize file paths lazily to avoid circular imports
    
    server_url = config["MCP_SERVER_URL"]
    api_key = config["OPENAI_API_KEY"]
    model = config["GATHERER_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    max_iterations = config["MAX_ITERATIONS"]
    extra_body = config.get("OPENAI_EXTRA_BODY", {})
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AETHER] Error: MCP_SERVER_URL must start with http:// or https://")
        return False

    if not api_key:
        print("[AETHER] Error: OPENAI_API_KEY not set in config.")
        return False

    custom_user_prompt = config.get("custom_user_prompt", "").strip()

    # --- Function Filter List is now imported from shared module ---
    while True:
        try:
            async with sse_client(server_url) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    print("[AETHER] Connected to MCP server.")

                    idb_metadata_raw = await mcp_get_tool_text_content(session, "get_metadata")
                    idb_metadata = idb_metadata_raw if idb_metadata_raw else "Not available."
                    print(f"[AETHER] [Gatherer] Retrieved IDB metadata: {idb_metadata[:300]}...")  # Print first 300 chars

                    current_func_details = await mcp_get_tool_json_content(session, "get_current_function")
                    if not current_func_details or "address" not in current_func_details or "name" not in current_func_details:
                        print("[AETHER] Error: Could not get current function details from MCP.")
                        return False

                    initial_func_name = current_func_details["name"]
                    initial_func_addr = current_func_details["address"]
                    print(f"[AETHER] Starting analysis with function: {initial_func_name} at {initial_func_addr}")

                    # Get initial pseudocode using custom implementation
                    initial_pseudocode_container = {"code": ""}
                    
                    def _get_initial_pseudocode_sync():
                        try:
                            pseudocode = custom_get_pseudocode(initial_func_addr)
                            if pseudocode:
                                initial_pseudocode_container["code"] = pseudocode
                                return True
                        except Exception as e:
                            print(f"[AETHER] Error getting initial pseudocode: {e}")
                        return False
                    
                    success = ida_kernwin.execute_sync(_get_initial_pseudocode_sync, ida_kernwin.MFF_READ)
                    
                    if not success or not initial_pseudocode_container["code"]:
                        print(f"[AETHER] Error: Could not decompile initial function {initial_func_name}.")
                        return False

                    pseudocode_store: Dict[str, str] = {}
                    processed_functions = set()  # Track functions we've already processed

                    pseudocode_store[initial_func_name] = strip_and_reformat_pseudocode(initial_pseudocode_container["code"])
                    processed_functions.add(initial_func_name.lower())  # Normalize function name for comparison
                    call_tree_root = None
                    call_tree_root: Node = Node(name=initial_func_name, address=initial_func_addr)

                    try:
                        with open(PROMPT_GATHERER, "r", encoding="utf-8") as f:
                            prompt_template = f.read()
                    except FileNotFoundError:
                        print(f"[AETHER] Error: gatherer-prompt.txt not found at {PROMPT_GATHERER}")
                        return False

                    full_llm_responses = []  # Store all LLM responses for history

                    for i in range(max_iterations):
                        print(f"[AETHER] [Gatherer] Iteration {i+1}/{max_iterations}")
                        tree_str = format_call_tree_ascii(call_tree_root)
                        pseudocode_listing_str = format_pseudocode_listing(pseudocode_store)
                        metadata_section = f"IDB METADATA:\n{idb_metadata}\n\n"
                        current_prompt_content = prompt_template.replace("{FN_NAME}", initial_func_name)
                        current_prompt_content = current_prompt_content.replace("{TREE}", "CALL TREE:\n" + tree_str if "{TREE}" in current_prompt_content else metadata_section + "CALL TREE:\n" + tree_str)
                        current_prompt_content = current_prompt_content.replace("{CODES}", pseudocode_listing_str if "{CODES}" in current_prompt_content else pseudocode_listing_str)
                        if "IDB METADATA:" not in current_prompt_content:
                            current_prompt_content = metadata_section + current_prompt_content

                        # --- Insert custom user prompt if provided ---
                        if custom_user_prompt:
                            current_prompt_content += (
                                "\n\n---\n"
                                "USER-PROVIDED ADDITIONAL CONTEXT FOR GATHERER:\n"
                                f"{custom_user_prompt}\n"
                                "---\n"
                            )

                        # --- VERBOSE LOGGING ---
                        try:
                            with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                                vf.write(f"\n--- Iteration {i+1} ---\n")
                                vf.write(current_prompt_content)
                                vf.write("\n--- END PROMPT ---\n")
                        except Exception as e:
                            print(f"[AETHER] Error writing to verbose.txt: {e}")

                        # Print the function call tree to the IDA console after each iteration
                        print(f"[AETHER] [Gatherer] Function call tree after iteration {i+1}:\n{tree_str}")

                        llm_response_text = call_openai_llm_gatherer(current_prompt_content, api_key, model, base_url, extra_body, custom_ca_cert_path, client_cert_path, client_key_path)
                        if llm_response_text:
                            full_llm_responses.append(llm_response_text)
                        
                        if not llm_response_text:
                            print("[AETHER] [Gatherer] No response from LLM. Ending iteration.")
                            continue

                        commands, done_triggered = parse_llm_response(llm_response_text)
                        if done_triggered:
                            print("[AETHER] [Gatherer] LLM signaled DONE. Exiting gathering loop.")
                            break

                        if not commands:
                            print("[AETHER] [Gatherer] No new functions requested by LLM in this iteration.")

                        for command in commands:
                            if command["type"] == "add":
                                func_to_add_name_llm = command["name"]
                                source_func_name = command["source"]
                                
                                # Check if function is already processed (case-insensitive)
                                if func_to_add_name_llm.lower() in processed_functions:
                                    print(f"[AETHER] [Gatherer] Function '{func_to_add_name_llm}' already processed. Skipping duplicate (but may still appear in call tree).")
                                    continue
                                    
                                func_details = await mcp_get_tool_json_content(session, "get_function_by_name", {"name": func_to_add_name_llm})
                                if not func_details or "address" not in func_details:
                                    print(f"[AETHER] [Gatherer] Could not get details for '{func_to_add_name_llm}'. Skipping.")
                                    continue
                                actual_func_addr = func_details["address"]
                                actual_func_name = func_details.get("name", func_to_add_name_llm)
                                
                                # Check again with actual function name (case-insensitive)
                                if actual_func_name.lower() in processed_functions:
                                    print(f"[AETHER] [Gatherer] Function '{actual_func_name}' already processed. Skipping duplicate (but may still appear in call tree).")
                                    
                                    # Even if we skip adding to pseudocode store, we still need to add to call tree
                                    source_node = call_tree_root.find_node(source_func_name)
                                    if source_node:
                                        child_exists = any(child.name.lower() == actual_func_name.lower() for child in source_node.children)
                                        if not child_exists:
                                            new_node = Node(name=actual_func_name, address=actual_func_addr, parent_name=source_node.name)
                                            source_node.add_child(new_node)
                                    continue
                                    
                                # Get new pseudocode using custom implementation
                                new_pseudocode_container = {"code": ""}
                                
                                def _get_new_pseudocode_sync():
                                    try:
                                        pseudocode = custom_get_pseudocode(actual_func_addr)
                                        if pseudocode:
                                            new_pseudocode_container["code"] = pseudocode
                                            return True
                                    except Exception as e:
                                        print(f"[AETHER] Error getting pseudocode for {actual_func_name}: {e}")
                                    return False
                                
                                success = ida_kernwin.execute_sync(_get_new_pseudocode_sync, ida_kernwin.MFF_READ)
                                
                                if not success or not new_pseudocode_container["code"]:
                                    print(f"[AETHER] [Gatherer] Could not decompile {actual_func_name} at {actual_func_addr}. Skipping.")
                                    continue
                                
                                print(f"[AETHER] [Gatherer] Added function: {actual_func_name} (called by {source_func_name})")
                                pseudocode_store[actual_func_name] = strip_and_reformat_pseudocode(new_pseudocode_container["code"])
                                processed_functions.add(actual_func_name.lower())  # Add to processed set
                                
                                # Retry logic for source function not found in tree
                                source_node = call_tree_root.find_node(source_func_name)
                                retry_count = 0
                                max_retries = 3
                                
                                while not source_node and retry_count < max_retries:
                                    retry_count += 1
                                    print(f"[AETHER] [Gatherer] Source function '{source_func_name}' not found in tree (attempt {retry_count}/{max_retries}). Searching for alternative parent...")
                                    
                                    # Try to find any existing function that might be a suitable parent
                                    # Look for functions already in pseudocode_store that might contain calls to the target function
                                    alternative_parent = None
                                    for existing_func in pseudocode_store.keys():
                                        if existing_func != actual_func_name:
                                            existing_node = call_tree_root.find_node(existing_func)
                                            if existing_node:
                                                alternative_parent = existing_func
                                                source_node = existing_node
                                                print(f"[AETHER] [Gatherer] Using '{alternative_parent}' as alternative parent for '{actual_func_name}'")
                                                break
                                    
                                    if not source_node and retry_count < max_retries:
                                        print(f"[AETHER] [Gatherer] Retry {retry_count}: Still cannot find suitable parent for '{actual_func_name}'. Retrying...")
                                        await asyncio.sleep(1)  # Brief pause before retry
                                

                                if source_node:
                                    child_exists = any(child.name == actual_func_name for child in source_node.children)
                                    if not child_exists:
                                        new_node = Node(name=actual_func_name, address=actual_func_addr, parent_name=source_node.name)
                                        source_node.add_child(new_node)
                                else:
                                    print(f"[AETHER] [Gatherer] CRITICAL ERROR: After {max_retries} attempts, could not find source function '{source_func_name}' or suitable alternative in tree. Cannot add '{actual_func_name}'. This may indicate a structural issue with the call tree. Halting analysis.")
                                    print(f"[AETHER] [Gatherer] Current tree functions: {[node.name for node in [call_tree_root] + call_tree_root.children]}")
                                    return False, None, None

                    # Before generating final output, log the pseudocode store contents
                    print(f"[AETHER] [Gatherer] Processed {len(pseudocode_store)} unique functions for pseudocode listing.")
                    
                    final_tree_str = format_call_tree_ascii(call_tree_root)
                    final_pseudocode_listing_str = format_pseudocode_listing(pseudocode_store)
                    
                    # Show results dialog to user and get their choice
                    # We need to handle this differently due to IDA threading constraints
                    user_choice = "continue"  # Default choice
                    
                    # Store dialog results in a container that can be accessed from both threads
                    dialog_result_container = {"choice": "continue", "completed": False}
                    
                    def show_results_dialog():
                        try:
                            dlg = GatheringResultsDialog(final_tree_str, pseudocode_store)
                            
                            # Connect to the main application to ensure proper parenting
                            app = QtWidgets.QApplication.instance()
                            if app:
                                dlg.setParent(None)  # No parent for top-level dialog
                                dlg.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.WindowStaysOnTopHint)
                            
                            result = dlg.exec_()
                            
                            if result == QtWidgets.QDialog.Accepted:
                                dialog_result_container["choice"] = dlg.get_user_choice()
                            elif result == QtWidgets.QDialog.Rejected:
                                dialog_result_container["choice"] = "cancel"
                            else:
                                # Handle unexpected results
                                print(f"[AETHER] [Gatherer] Dialog returned unexpected result: {result}")
                                dialog_result_container["choice"] = "continue"
                                
                            dialog_result_container["completed"] = True
                            return True
                            
                        except Exception as e:
                            print(f"[AETHER] [Gatherer] Error showing results dialog: {e}")
                            traceback.print_exc()
                            dialog_result_container["choice"] = "continue"
                            dialog_result_container["completed"] = True
                            return False
                    
                    # Execute dialog on main thread and wait for completion
                    ida_kernwin.execute_sync(show_results_dialog, ida_kernwin.MFF_READ)
                    
                    # Wait for dialog completion with timeout
                    timeout_count = 0
                    max_timeout = 100  # 10 seconds (100 * 0.1)
                    while not dialog_result_container["completed"] and timeout_count < max_timeout:
                        await asyncio.sleep(0.1)
                        timeout_count += 1
                    
                    if not dialog_result_container["completed"]:
                        print("[AETHER] [Gatherer] Dialog timeout, defaulting to continue")
                        user_choice = "continue"
                    else:
                        user_choice = dialog_result_container["choice"]
                    
                    print(f"[AETHER] [Gatherer] User choice: {user_choice}")
                    
                    if user_choice == "retry":
                        print("[AETHER] [Gatherer] User chose to retry gathering. Restarting...")
                        # Clear current state and restart (recursive call with same config)
                        continue
                    elif user_choice == "cancel":
                        print("[AETHER] [Gatherer] User cancelled the analysis process.")
                        return False, None, None
                    else:
                        print("[AETHER] [Gatherer] User chose to continue with gathered functions.")
                        break
        except Exception as e:
            print(f"[AETHER] [Gatherer] Unexpected error: {e}")
            traceback.print_exc()
            return False, None, None
                    
    # Write output files (only if continuing)
    try:
        with open(CTX_FILE_PATH, "w", encoding="utf-8") as f:
            f.write("FINAL CALL TREE:\n")
            f.write(final_tree_str)
            f.write("\n\nFINAL PSEUDOCODE LISTING:\n")
            f.write(final_pseudocode_listing_str)
    except Exception as e:
        print(f"[AETHER] Error writing output files: {e}")
        return False, None, None
    print("[AETHER] [Gatherer] Gathering complete.")
    return True, initial_func_name, "\n\n".join(full_llm_responses)

# Note: The gatherer doesn't use the same default selection logic as manual gatherer
# since it's LLM-driven, but we should update any filtering logic to be consistent