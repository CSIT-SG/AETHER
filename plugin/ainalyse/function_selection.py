import traceback
from typing import Dict, List, Optional, Set

import ida_kernwin
import idaapi
import idautils
import idc
from PyQt5 import QtCore, QtWidgets

from ainalyse.preprocessor import format_pseudocode_listing_for_ai_decomp

# --- Internal imports ---
from ainalyse.custom_set_cmt import custom_get_pseudocode
from ainalyse.manual_gatherer import Node, format_call_tree_ascii

# --- Shared Function Filter List ---
FILTERED_FUNCTIONS = [
    # Standard C library functions
    "memset", "memcpy", "strcpy", "strcmp", "strlen", "strcat", "sprintf", "printf", "scanf",
    "malloc", "free", "calloc", "realloc", "exit", "abort", "atoi", "atol", "strtol",
    # Windows API common functions
    "GetModuleHandle", "GetProcAddress", "LoadLibrary", "FreeLibrary", "CreateFile",
    "ReadFile", "WriteFile", "CloseHandle", "VirtualAlloc", "VirtualFree",
    # DLL prefixes and common imports
    "ntdll", "kernel32", "user32", "advapi32", "msvcrt", "ws2_32",
    # Dot-prefixed imports
    ".memset", ".memcpy", ".strcpy", ".strcmp", ".strlen", ".strcat", ".sprintf", ".printf"
]

# --- Extended Filter List for "Select All Non-Keyword" ---
EXTENDED_FILTERED_FUNCTIONS = FILTERED_FUNCTIONS + [
    # Additional common functions for stricter filtering
    "puts", "putchar", "getchar", "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
    "strdup", "strncat", "strncpy", "strncmp", "strchr", "strstr", "strtok", "sscanf",
    "fprintf", "snprintf", "vprintf", "vsprintf", "time", "clock", "sleep", "usleep",
    # Math functions
    "sin", "cos", "tan", "sqrt", "pow", "exp", "log", "floor", "ceil", "abs", "fabs",
    # Thread functions
    "pthread_create", "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock",
    # Network functions
    "socket", "bind", "listen", "accept", "connect", "send", "recv", "close",
    # Additional Windows API
    "MessageBox", "GetLastError", "SetLastError", "GetCurrentProcess", "GetCurrentThread"
]

def get_default_selection_criteria():
    """Get the default criteria for function selection."""
    return lambda func_name: (func_name in ["main", "start", "WinMain"] or 
                              func_name.startswith("sub_"))

def get_extended_filter_criteria():
    """Get criteria for filtering out keyword functions (stricter than default)."""
    def should_filter(func_name):
        # Check against extended filter list
        for filtered_name in EXTENDED_FILTERED_FUNCTIONS:
            if filtered_name.lower() in func_name.lower():
                return True
        return False
    return should_filter

def should_filter_function(func_name: str, use_extended_filter: bool = False) -> bool:
    """Check if a function should be filtered out based on name."""
    filter_list = EXTENDED_FILTERED_FUNCTIONS if use_extended_filter else FILTERED_FUNCTIONS
    
    for filtered_name in filter_list:
        if filtered_name.lower() in func_name.lower():
            return True
    return False

def get_function_callees(func_addr_str: str, parent_func_name: Optional[str] = None) -> List[Dict[str, str]]:
    """Get callees of a function using IDA API. Must be called from main thread."""
    try:
        func_addr = int(func_addr_str, 16)
        func = idaapi.get_func(func_addr)
        if not func:
            return []
        
        callee_functions = set()
        # Iterate over every instruction in the function
        for instruction_ea in idautils.FuncItems(func.start_ea):
            # Get all references from this single instruction
            for xref in idautils.XrefsFrom(instruction_ea, 0):
                # Check if the reference destination is a function
                callee_func = idaapi.get_func(xref.to)
                if callee_func:
                    # Add the start address of the function to the set
                    callee_functions.add(callee_func.start_ea)
        
        callees = []
        # Convert to list with names and filter
        for func_ea in sorted(list(callee_functions)):
            func_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
            if func_name:
                # Filter out unwanted functions
                if should_filter_function(func_name):
                    continue
                
                # Prevent function from being a child of itself
                if parent_func_name and func_name == parent_func_name:
                    continue
                
                callees.append({
                    'name': func_name,
                    'address': hex(func_ea)
                })
        
        return callees[:50]  # Limit to 50 callees to avoid overwhelming UI
        
    except Exception as e:
        print(f"[AETHER] Error getting callees for {func_addr_str}: {e}")
        return []

def collect_functions_with_default_criteria(starting_func_addr: str, starting_func_name: str, 
                                          depth: int = 0, max_depth: int = 5, 
                                          processed: Optional[Set[str]] = None) -> List[Dict[str, str]]:
    """Collect functions using default selection criteria. Must be called from main thread."""
    if processed is None:
        processed = set()
    
    selected_functions = []
    
    def collect_recursive(func_addr, func_name, current_depth):
        if current_depth >= max_depth or func_addr in processed:
            return
        
        processed.add(func_addr)
        
        # Get callees for this function
        callees = get_function_callees(func_addr, func_name)
        
        # Apply default selection logic
        default_criteria = get_default_selection_criteria()
        
        for callee_info in callees:
            callee_name = callee_info['name']
            callee_addr = callee_info['address']
            
            if default_criteria(callee_name):
                # Check if not already in selected functions
                if not any(f['name'] == callee_name for f in selected_functions):
                    selected_functions.append({
                        'name': callee_name,
                        'address': callee_addr
                    })
                    print(f"[AETHER] Auto-selected function: {callee_name}")
                    
                    # Recursively process this function's callees
                    collect_recursive(callee_addr, callee_name, current_depth + 1)
    
    # Add the starting function
    selected_functions.append({
        'name': starting_func_name,
        'address': starting_func_addr
    })
    
    # Collect functions recursively
    collect_recursive(starting_func_addr, starting_func_name, depth)
    
    return selected_functions

def collect_functions_for_generate_report(starting_func_addr: str, starting_func_name: str, 
                                          depth: int = 0, max_depth: int = 5, 
                                          processed: Optional[Set[str]] = None) -> List[Dict[str, str]]:
    """Collect functions using default selection criteria. Must be called from main thread."""
    imports = []

    def callback(ea, func_name, ordinal):
        imports.append(func_name.lstrip("_").split("@")[0])
        return True

    for i in range(idaapi.get_import_module_qty()):
        idaapi.enum_import_names(i, callback)

    if processed is None:
        processed = set()
    
    selected_functions = []
    
    def collect_recursive(func_addr, func_name, current_depth):
        if current_depth >= max_depth or func_addr in processed:
            return
        
        processed.add(func_addr)
        
        # Get callees for this function
        callees = get_function_callees(func_addr, func_name)
        
        # Apply default selection logic
        
        for callee_info in callees:
            callee_name = callee_info['name']
            callee_addr = callee_info['address']
            
            # Check if not already in selected functions
            if not any(f['name'] == callee_name for f in selected_functions):
                # Check if not default
                if not (callee_name.startswith("sub_") or callee_name.lstrip("_") in imports):
                    selected_functions.append({
                        'name': callee_name,
                        'address': callee_addr
                    })
                    print(f"[AInalyse] Auto-selected function: {callee_name}")
                
                # Recursively process this function's callees
                collect_recursive(callee_addr, callee_name, current_depth + 1)
    
    # Add the starting function
    selected_functions.append({
        'name': starting_func_name,
        'address': starting_func_addr
    })
    
    # Collect functions recursively
    collect_recursive(starting_func_addr, starting_func_name, depth)
    
    return selected_functions

class FunctionTreeItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, function_name, address):
        super(FunctionTreeItem, self).__init__([f"{function_name} [{address}]"])
        self.function_name = function_name
        self.address = address
        self.callees_loaded = False
        self.setCheckState(0, QtCore.Qt.Unchecked)
        self.setFlags(self.flags() | QtCore.Qt.ItemIsUserCheckable)

class FunctionSelectionDialog(QtWidgets.QDialog):
    """Reusable dialog for selecting functions for analysis."""
    
    def __init__(self, current_function_name, current_function_addr, window_title="Select Functions", parent=None, onlyTopLevel=False) :
        super(FunctionSelectionDialog, self).__init__()
        self.setWindowTitle(window_title)
        self.setMinimumSize(600, 500)
        self.current_function_name = current_function_name
        self.current_function_addr = current_function_addr
        self.selected_functions = []
        self.onlyTopLevel = onlyTopLevel
        
        layout = QtWidgets.QVBoxLayout()
        
        # Header
        header_label = QtWidgets.QLabel(f"Select functions to analyze starting from '{current_function_name}':")
        header_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        # Instructions
        info_label = QtWidgets.QLabel("Functions named 'main', 'start', 'WinMain' or starting with 'sub_' are selected by default. Use 'Reset to Default' to restore default selection.")
        if (self.onlyTopLevel) : info_label = QtWidgets.QLabel("The root function is selected by default. Use 'Reset to Default' to restore default selection.")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Selection buttons (above tree view, left-aligned)
        selection_button_layout = QtWidgets.QHBoxLayout()
        
        self.reset_button = QtWidgets.QPushButton("Reset to Default")
        self.reset_button.setToolTip("Restores default selection")
        self.reset_button.clicked.connect(self.reset_to_default)
        selection_button_layout.addWidget(self.reset_button)
        
        self.select_all_non_keyword_button = QtWidgets.QPushButton("Select All Non-Common")
        self.select_all_non_keyword_button.setToolTip("Selects all functions except common ones like puts, getchar, fopen, fread, fwrite, etc...")
        self.select_all_non_keyword_button.clicked.connect(self.select_all_non_keyword)
        selection_button_layout.addWidget(self.select_all_non_keyword_button)
        
        self.select_aire_button = QtWidgets.QPushButton("Select aire_*")
        self.select_aire_button.setToolTip("Selects all functions whose names start with 'aire_'")
        self.select_aire_button.clicked.connect(self.select_aire_functions)
        selection_button_layout.addWidget(self.select_aire_button)
        
        self.deselect_all_button = QtWidgets.QPushButton("Deselect All")
        self.deselect_all_button.clicked.connect(self.deselect_all)
        selection_button_layout.addWidget(self.deselect_all_button)
        
        selection_button_layout.addStretch()  # Push buttons to the left
        
        layout.addLayout(selection_button_layout)
        
        # Tree widget
        self.tree_widget = QtWidgets.QTreeWidget()
        self.tree_widget.setHeaderLabel("Function Call Tree")
        self.tree_widget.itemExpanded.connect(self.on_item_expanded)
        layout.addWidget(self.tree_widget)
        
        # Add root function
        root_item = FunctionTreeItem(current_function_name, current_function_addr)
        root_item.setCheckState(0, QtCore.Qt.Checked)  # Root is always selected
        self.tree_widget.addTopLevelItem(root_item)
        
        # Auto-expand to 5 layers deep and apply default selection
        self.auto_expand_and_select(root_item, 0, 5)
        
        # Run reset to default selection to ensure defaults are applied on open
        self.reset_to_default()
        
        # Bottom buttons
        button_layout = QtWidgets.QHBoxLayout()
        
        self.dump_to_file_button = QtWidgets.QPushButton("Dump to File")
        self.dump_to_file_button.clicked.connect(self.dump_to_file)
        button_layout.addWidget(self.dump_to_file_button)
        
        button_layout.addStretch()
        
        self.analyze_button = QtWidgets.QPushButton("Confirm Selection")
        self.analyze_button.clicked.connect(self.accept)
        button_layout.addWidget(self.analyze_button)
        
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def populate_callees(self, parent_item):
        """Populate callees for a function item."""
        if parent_item.callees_loaded:
            return
        
        callees = get_function_callees(parent_item.address, parent_item.function_name)
        for callee in callees:
            child_item = FunctionTreeItem(callee['name'], callee['address'])
            parent_item.addChild(child_item)
        
        parent_item.callees_loaded = True
    
    def on_item_expanded(self, item):
        """Handle item expansion to lazily load callees."""
        if isinstance(item, FunctionTreeItem):
            self.populate_callees(item)
            # Recursively populate for all children
            for i in range(item.childCount()):
                child = item.child(i)
                if isinstance(child, FunctionTreeItem):
                    self.populate_callees(child)
    
    def auto_expand_and_select(self, item, current_depth, max_depth):
        """Auto-expand to specified depth and apply default selection."""
        if not isinstance(item, FunctionTreeItem) or current_depth >= max_depth:
            return
        
        # Populate callees for this item
        self.populate_callees(item)
        
        # Expand this item
        item.setExpanded(True)
        
        # Apply default selection based on function name
        default_criteria = get_default_selection_criteria()
        if default_criteria(item.function_name):
            item.setCheckState(0, QtCore.Qt.Checked)
        else:
            item.setCheckState(0, QtCore.Qt.Unchecked)
        
        # Recursively process children
        for i in range(item.childCount()):
            child = item.child(i)
            if isinstance(child, FunctionTreeItem):
                self.auto_expand_and_select(child, current_depth + 1, max_depth)
    
    def reset_to_default(self):
        """Reset selection to default (main, start, WinMain and sub_* functions)"""
        def reset_recursive(item):
            if isinstance(item, FunctionTreeItem):
                # Apply default selection logic
                default_criteria = get_default_selection_criteria()
                if (default_criteria(item.function_name) and not self.onlyTopLevel):
                    item.setCheckState(0, QtCore.Qt.Checked)
                else:
                    # Root function should always be checked
                    if ((item.function_name == self.current_function_name) and self.onlyTopLevel) :
                        item.setCheckState(0, QtCore.Qt.Checked)
                    else:
                        item.setCheckState(0, QtCore.Qt.Unchecked)
                
                # Recursively process children
                for i in range(item.childCount()):
                    reset_recursive(item.child(i))
        
        for i in range(self.tree_widget.topLevelItemCount()):
            reset_recursive(self.tree_widget.topLevelItem(i))
    
    def select_all_non_keyword(self):
        """Select all functions except those containing common keywords."""
        def select_recursive(item):
            if isinstance(item, FunctionTreeItem):
                # Always check root function
                if item.function_name == self.current_function_name:
                    item.setCheckState(0, QtCore.Qt.Checked)
                else:
                    # Check if function should be filtered (using extended filter)
                    if should_filter_function(item.function_name, use_extended_filter=True):
                        item.setCheckState(0, QtCore.Qt.Unchecked)
                    else:
                        item.setCheckState(0, QtCore.Qt.Checked)
                
                # Only process children that are ALREADY loaded - don't populate new ones
                # This prevents hanging and only works on displayed functions
                for i in range(item.childCount()):
                    child = item.child(i)
                    if isinstance(child, FunctionTreeItem):
                        select_recursive(child)
        
        for i in range(self.tree_widget.topLevelItemCount()):
            select_recursive(self.tree_widget.topLevelItem(i))
    
    def select_aire_functions(self):
        """Select all functions whose names start with 'aire_' (adds to current selection)."""
        def select_recursive(item):
            if isinstance(item, FunctionTreeItem):
                # Always keep root function checked
                if item.function_name == self.current_function_name:
                    item.setCheckState(0, QtCore.Qt.Checked)
                else:
                    # Check if function name starts with 'aire_' - if so, add it to selection
                    if item.function_name.startswith("aire_"):
                        item.setCheckState(0, QtCore.Qt.Checked)
                    # Don't modify other functions - keep their current state
                
                # Only process children that are ALREADY loaded - don't populate new ones
                # This prevents hanging and only works on displayed functions
                for i in range(item.childCount()):
                    child = item.child(i)
                    if isinstance(child, FunctionTreeItem):
                        select_recursive(child)
        
        for i in range(self.tree_widget.topLevelItemCount()):
            select_recursive(self.tree_widget.topLevelItem(i))
    
    def deselect_all(self, keepRootFunction = True):
        """Deselect all functions except possibly the root function."""
        def deselect_recursive(item):
            if isinstance(item, FunctionTreeItem):
                # Always keep root function checked
                if ((item.function_name == self.current_function_name) and keepRootFunction) :
                    item.setCheckState(0, QtCore.Qt.Checked)
                else:
                    item.setCheckState(0, QtCore.Qt.Unchecked)
                
                # Recursively process children
                for i in range(item.childCount()):
                    deselect_recursive(item.child(i))
        
        # Batch updates for better rendering performance
        self.tree_widget.blockSignals(True)
        try:
            for i in range(self.tree_widget.topLevelItemCount()):
                deselect_recursive(self.tree_widget.topLevelItem(i))
        finally:
            self.tree_widget.blockSignals(False)
    
    def get_selected_functions(self):
        """Get list of selected functions."""
        selected = []
        
        def collect_checked(item):
            if isinstance(item, FunctionTreeItem) and item.checkState(0) == QtCore.Qt.Checked:
                selected.append({
                    'name': item.function_name,
                    'address': item.address
                })
            for i in range(item.childCount()):
                collect_checked(item.child(i))
        
        for i in range(self.tree_widget.topLevelItemCount()):
            collect_checked(self.tree_widget.topLevelItem(i))
        
        return selected
    
    def dump_to_file(self):
        """Generate and save the exact call tree and pseudocode listing that would be sent to the LLM."""
        # Get the selected functions
        selected_functions = self.get_selected_functions()
        
        if not selected_functions:
            QtWidgets.QMessageBox.warning(self, "No Functions Selected", 
                                         "Please select at least one function before dumping to file.")
            return
        
        # Ask for the file path
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save Call Tree and Pseudocode (LLM Format)", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if not file_path:
            return  # User cancelled
        
        try:
            # Find the root function (should be the first one in our selected list)
            root_function = selected_functions[0]
            root_func_name = root_function["name"]
            root_func_addr = root_function["address"]
            
            # Build the call tree
            call_tree_root = Node(name=root_func_name, address=root_func_addr)
            
            # Build call relationships
            call_relationships = {}
            
            for func_info in selected_functions:
                func_name = func_info["name"]
                func_addr = func_info["address"]
                
                # Get callees for this function
                callees = get_function_callees(func_addr, func_name)
                
                # Only include callees that are in our selected functions list
                selected_callees = []
                for callee in callees:
                    if any(f["name"] == callee["name"] for f in selected_functions):
                        selected_callees.append(callee["name"])
                
                if selected_callees:
                    call_relationships[func_name] = selected_callees
            
            # Build the hierarchical tree
            def build_tree_recursive(parent_node, parent_func_name, processed_nodes):
                if parent_func_name in processed_nodes:
                    return
                
                processed_nodes.add(parent_func_name)
                callees = call_relationships.get(parent_func_name, [])
                
                for callee_name in callees:
                    # Find the address for this callee
                    callee_addr = None
                    for func_info in selected_functions:
                        if func_info["name"] == callee_name:
                            callee_addr = func_info["address"]
                            break
                    
                    if callee_addr:
                        # Check if child already exists
                        child_exists = any(child.name == callee_name for child in parent_node.children)
                        if not child_exists:
                            child_node = Node(name=callee_name, address=callee_addr, parent_name=parent_func_name)
                            parent_node.add_child(child_node)
                            # Recursively build tree for this child
                            build_tree_recursive(child_node, callee_name, processed_nodes)
            
            processed_nodes = set()
            build_tree_recursive(call_tree_root, root_func_name, processed_nodes)
            
            # Format the call tree (same as what LLM receives)
            call_tree_str = format_call_tree_ascii(call_tree_root)
            
            # Get pseudocode for each function using the same approach as the LLM input
            pseudocode_store = {}
            function_address_map = {}  # Map function names to addresses
            processed_functions = set()  # Track to avoid duplicates
            
            for func_info in selected_functions:
                func_name = func_info["name"]
                func_addr = func_info["address"]
                
                # Check for duplicates (same as in AI decomp)
                if func_name.lower() in processed_functions:
                    continue
                    
                # Store the function name to address mapping
                function_address_map[func_name] = func_addr
                
                # Container for pseudocode
                pseudocode_container = {"code": ""}
                
                def _get_pseudocode_sync():
                    try:
                        pseudocode = custom_get_pseudocode(func_addr)
                        if pseudocode:
                            pseudocode_container["code"] = pseudocode
                            return True
                    except Exception as e:
                        print(f"Error decompiling {func_name}: {e}")
                    return False
                
                success = ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
                
                if success and pseudocode_container["code"]:
                    pseudocode_store[func_name] = pseudocode_container["code"]
                    processed_functions.add(func_name.lower())
            
            # Format the pseudocode listing exactly like what the AI receives
            pseudocode_listing_str = format_pseudocode_listing_for_ai_decomp(pseudocode_store, function_address_map)
            
            # Format exactly as it appears in the LLM prompt
            full_content = f"CALL TREE:\n{call_tree_str}\n\n{pseudocode_listing_str}"
            
            # Write to file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(full_content)
            
            QtWidgets.QMessageBox.information(self, "Success", 
                                            f"Successfully saved the exact LLM input format to {file_path}")
        
        except Exception as e:
            import logging
            traceback.print_exc()
            QtWidgets.QMessageBox.critical(self, "Error", 
                                        f"An error occurred while saving to file: {str(e)}")
            traceback.print_exc()
            QtWidgets.QMessageBox.critical(self, "Error", f"An error occurred while saving to file: {str(e)}")
