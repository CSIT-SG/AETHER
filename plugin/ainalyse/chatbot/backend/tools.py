"""
This module defines the tools available to the chatbot agent.
Each tool is a function that takes the agent's state and other arguments.
"""
from enum import StrEnum
from typing import Optional

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_name
import idautils
import idc

from PyQt5 import QtWidgets
from .core import AgentState, TaskStatus
from ...python_script_generation import DeobfuscateHandler

try:
    from ...indexing import FunctionIndexManager
    _HAS_INDEXING = True
except ImportError:
    _HAS_INDEXING = False

# --- Tool Definitions for LLM ---

class ToolNames(StrEnum):
    ADD_ACTION_PLAN = "add_action_plan"
    ADD_TASK_TO_PLAN = "add_task_to_plan"
    UPDATE_TASK = "update_task"
    REMOVE_TASK_FROM_PLAN = "remove_task_from_plan"
    REMOVE_ACTION_PLAN = "remove_action_plan"
    ADD_SHORT_TERM_MEMORY = "add_short_term_memory"
    REMOVE_SHORT_TERM_MEMORY = "remove_short_term_memory"
    LIST_FUNCTIONS = "list_functions"
    GET_FUNCTION_PSEUDOCODE = "get_function_pseudocode"
    ADD_TO_FUNCTION_LIST = "add_to_function_list"
    REMOVE_FROM_FUNCTION_LIST = "remove_from_function_list"
    GET_DATA_AT_ADDRESS = "get_data_at_address"
    GET_XREFS_TO = "get_xrefs_to"
    RUN_FASTLOOK_ANNOTATION = "run_fastlook_annotation"
    RUN_CUSTOM_ANNOTATION = "run_custom_annotation"
    SAVE_SUMMARY = "save_summary"
    SEARCH_INDEXED_FUNCTIONS = "search_indexed_functions"
    GET_FUNCTION_INDEX_SUMMARY = "get_function_index_summary"
    GET_INDEXED_FUNCTION_DETAIL = "get_indexed_function_detail"
    ASK_INDEX_AGENT = "ask_index_agent"
    GENERATE_PYTHON_SCRIPT = "generate_python_script"

# --- Tool Implementations ---

def add_action_plan(state: AgentState, plan_index: str, description: str) -> str:
    """Creates and adds a new action plan to the agent's list of plans."""
    try:
        index = int(plan_index)
        state.add_action_plan(description, [], index)
        return f"Action plan {index} added: {description}"
    except ValueError:
        print(f"[Agent] Error: Invalid plan_index '{plan_index}'. Must be an integer.")
        return f"Error: Invalid plan_index '{plan_index}'. Must be an integer."

def add_task_to_plan(state: AgentState, plan_index: str, task_index: str, description: str) -> str:
    """Adds a new task to a specific action plan, optionally at a given index."""
    try:
        p_index = int(plan_index)
        t_index = int(task_index)
        state.add_task_to_plan(p_index, description, t_index)
        return f"Task {t_index} added to plan {p_index}: {description}"
    except ValueError:
        print(f"[Agent] Error: Invalid plan_index '{plan_index}' or task_index '{task_index}'. Must be an integer.")
        return f"Error: Invalid plan_index '{plan_index}' or task_index '{task_index}'. Must be an integer."

def update_task(state: AgentState, plan_index: str, task_index: str, status: str) -> str:
    """Updates the status of a task. Status must be one of: 'Not Started', 'In Progress', 'Completed', 'Failed'."""
    try:
        p_index = int(plan_index)
        t_index = int(task_index)
        status_enum = TaskStatus(status)
        state.update_task(p_index, t_index, status_enum)
        return f"Task {t_index} in plan {p_index} updated to {status}"
    except ValueError:
        print(f"[Agent] Error: Invalid status '{status}' or index. plan_index and task_index must be integers.")
        return f"Error: Invalid status '{status}' or index. plan_index and task_index must be integers."

def remove_task_from_plan(state: AgentState, plan_index: str, task_index: str) -> str:
    """Removes a task from a specific action plan using its index."""
    try:
        p_index = int(plan_index)
        t_index = int(task_index)
        state.remove_task_from_plan(p_index, t_index)
        return f"Task {t_index} removed from plan {p_index}"
    except ValueError:
        print(f"[Agent] Error: Invalid plan_index '{plan_index}' or task_index '{task_index}'. Must be an integer.")
        return f"Error: Invalid plan_index '{plan_index}' or task_index '{task_index}'. Must be an integer."

def remove_action_plan(state: AgentState, plan_index: str) -> str:
    """Removes a specific action plan from the agent's state by its index."""
    try:
        p_index = int(plan_index)
        state.remove_action_plan(p_index)
        return f"Action plan {p_index} removed"
    except ValueError:
        print(f"[Agent] Error: Invalid plan_index '{plan_index}'. Must be an integer.")
        return f"Error: Invalid plan_index '{plan_index}'. Must be an integer."

def add_short_term_memory(state: AgentState, key: str, value: str) -> str:
    """Adds or updates a key-value pair in the agent's short-term memory for context."""
    try:
        state.add_short_term_memory(key, value)
        return f"Memory '{key}' added"
    except:
        print(f"[Agent] Error: Invalid key '{key}' or '{value}'.")
        return(f"[Agent] Error: Invalid key '{key}' or '{value}'.")

def remove_short_term_memory(state: AgentState, key: Optional[str] = None, index: Optional[str] = None) -> str:
    """Removes a memory entry by its key or its current numerical index."""
    if index is not None:
        try:
            int_index = int(index)
            state.remove_short_term_memory(key=key, index=int_index)
            return f"Memory at index {index} removed"
        except ValueError:
            print(f"[Agent] Error: Invalid index '{index}'. Must be an integer.")
            return f"Error: Invalid index '{index}'. Must be an integer."
    else:
        state.remove_short_term_memory(key=key, index=None)
        return f"Memory with key '{key}' removed"

def add_to_function_list(state: AgentState, func_name: str) -> str:
    """Adds a function to the analysis list."""
    return state.add_to_function_list(func_name)

def remove_from_function_list(state: AgentState, func_name: str) -> str:
    """Removes a function from the analysis list."""
    state.remove_from_function_list(func_name)
    return f"Function '{func_name}' removed from the list"

def list_functions(state: AgentState) -> str:
    """Lists all functions in the binary, returning their names and addresses."""
    functions = []
    def _list_functions_sync():
        for func_ea in idautils.Functions():
            functions.append({
                "name": ida_funcs.get_func_name(func_ea),
                "address": hex(func_ea)
            })
        return True
    
    # IDA API calls must be run on the main thread
    ida_kernwin.execute_sync(_list_functions_sync, ida_kernwin.MFF_READ)
    state.last_result = functions
    print(f"[Agent] Tool Result: list_functions -> {len(functions)} functions found.")
    return '\n'.join([f['name'] for f in functions])

def get_function_pseudocode(state: AgentState, function_name: str) -> str:
    """Gets the pseudocode for a specific function by its name."""
    code_container = {'code': None}
    def _get_pseudocode_sync():
        func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR,function_name)
        if func_ea == ida_idaapi.BADADDR:
            return None
        
        try:
            code_container['code']  = str(ida_hexrays.decompile(func_ea))
            return True
        except ida_hexrays.DecompilationFailure:
            return f"// Decompilation failed for {function_name}"
        return None

    # IDA API calls must be run on the main thread
    result = ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
    state.last_result = code_container['code']
    if code_container['code']:
        print(f"[Agent] Tool Result: get_function_pseudocode for '{function_name}' -> {len(code_container['code']) if result else 0} chars.")
        return code_container['code']
    else:
        print(f"[Agent] Tool Result: get_function_pseudocode for '{function_name}' -> function not found")
        return f"Function '{function_name}' not found."

def get_data_at_address(state: AgentState, location: str, count: str = "16") -> str:
    # Use a dictionary to store results across threads
    data_container = {"ea": None, "bytes": "No bytes found", "string": "No string found"}
    
    def _get_data_sync():
        try:
            # 1. Resolve Address
            try:
                ea = int(location, 16)
            except (ValueError, TypeError):
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, location)

            if ea == ida_idaapi.BADADDR:
                return 0  # CRITICAL: Always return an INT (0 for not found)

            data_container["ea"] = hex(ea)

            # 2. Resolve Count
            try:
                num = int(count)
            except:
                num = 16

            # 3. Get Bytes
            # Wrap this in its own try block because reading from imports/external EAs can crash
            try:
                raw_bytes = ida_bytes.get_bytes(ea, num)
                if raw_bytes:
                    data_container["bytes"] = raw_bytes.hex()
            except Exception as e:
                data_container["bytes"] = f"Error reading bytes: {str(e)}"

            # 4. Get String
            try:
                string_value = idc.get_strlit_contents(ea)
                if string_value:
                    data_container["string"] = string_value.decode('utf-8', errors='replace')
            except Exception as e:
                data_container["string"] = f"Error decoding: {str(e)}"
            return 1  # CRITICAL: Always return an INT (1 for success)

        except Exception as e:
            print(f"[Agent] Tool get_data_at_address error: {str(e)}")
            return 0
    # Execute and capture the return status
    status = ida_kernwin.execute_sync(_get_data_sync, ida_kernwin.MFF_READ)
    state.last_result = data_container
    if data_container["ea"]:
        result_str = (f"Data at {data_container['ea']}:\n"
                      f"Hex: {data_container['bytes']}\n"
                      f"String: {data_container['string']}")
        print(f"[Agent] Tool Result: get_data_at_address ->\n{result_str}")
        return result_str
    else:
        return f"Error: Could not resolve address/name '{location}'."

def get_xrefs_to(state: AgentState, location: str) -> str:
    """
    Finds all locations that reference or call the given address/name.
    Essential for tracing logic flow and identifying callers.
    """
    xrefs_found = []

    def _get_xrefs_sync():
        try:
            try:
                ea = int(location, 16)
            except (ValueError, TypeError):
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, location)

            if ea == ida_idaapi.BADADDR:
                return 0 

            # Iterate Xrefs
            for xref in idautils.XrefsTo(ea):
                # Map technical type IDs to human-readable context
                # 1 = Data_Offset, 2 = Data_Write, 3 = Data_Read, 
                # 16 = Code_Far_Call, 17 = Code_Near_Call, 21 = Code_Near_Jump
                ref_type = "Unknown"
                if xref.type == 1: ref_type = "Data_Offset"
                elif xref.type == 2: ref_type = "Data_Write"
                elif xref.type == 3: ref_type = "Data_Read"
                elif xref.type in [16, 17]: ref_type = "Code_Call"
                elif xref.type == 21: ref_type = "Code_Jump"

                caller_name = ida_name.get_name(xref.frm)
                if not caller_name:
                    caller_name = f"sub_{xref.frm:X}"
                
                xrefs_found.append({
                    "from": hex(xref.frm),
                    "name": caller_name,
                    "type": ref_type
                })
            return 1
        except Exception as e:
            print(f"[XREF ERROR] {str(e)}")
            return 0

    ida_kernwin.execute_sync(_get_xrefs_sync, ida_kernwin.MFF_READ)

    if not xrefs_found:
        return f"No cross-references found for '{location}'."

    # Format for LLM readability
    output = [f"Found {len(xrefs_found)} Xrefs to '{location}':"]
    for x in xrefs_found:
        output.append(f"  - {x['from']} in {x['name']} ({x['type']})")
    
    result_str = "\n".join(output)
    state.last_result = xrefs_found
    print(f"[Agent] Tool Result: get_xrefs_to ->\n{result_str}")
    return result_str


def _prepare_chatbot_annotation_context():
    """Prepare validated config and current function context for chatbot annotation tools."""
    from ... import load_config, validate_basic_config
    from ...utils import prepare_activate_context

    def _update_annotation_config(config):
        config["SINGLE_ANALYSIS_MODEL"] = config.get("SINGLE_ANALYSIS_MODEL") or config.get("OPENAI_MODEL")
        config["rename_filter_enabled"] = True

    return prepare_activate_context(load_config, validate_basic_config, _update_annotation_config)


def run_fastlook_annotation(state: AgentState) -> str:
    """Run FastLook-style annotation on the current function asynchronously."""
    from ... import add_analysis_entry
    from ...async_manager import schedule_ui_task
    from ...realtime.realtime import run_fast_look_analysis
    from ...utils import refresh_functions

    config, current_func_addr, current_func_name = _prepare_chatbot_annotation_context()
    if not config:
        return "Failed to start fastlook annotation: invalid config or no function at cursor."

    async def _chatbot_fastlook_thread():
        try:
            success, gatherer_out, annotator_out, structured_commands = await run_fast_look_analysis(
                config,
                current_func_name,
                current_func_addr,
            )
            if not success:
                print("[AETHER] [Chatbot] Fast look annotation failed.")
                return

            add_analysis_entry(
                gatherer_output=gatherer_out,
                annotator_output=annotator_out,
                starting_function=current_func_name,
                structured_data=structured_commands,
            )
            refresh_functions(fallback_func_addr=current_func_addr, log_prefix="[AETHER] [Chatbot]")
        except Exception as e:
            print(f"[AETHER] [Chatbot] Error running fastlook annotation: {e}")
            import traceback
            traceback.print_exc()

    task = schedule_ui_task(_chatbot_fastlook_thread())
    if task is None:
        return "Failed to queue fastlook annotation task."
    return f"Queued fastlook annotation for '{current_func_name}' at {current_func_addr}."


def run_custom_annotation(state: AgentState, user_advice: str) -> str:
    """Run custom realtime annotation for the current function using user guidance."""
    from ...async_manager import schedule_ui_task
    from ...realtime.realtime import run_custom_prompt_analysis
    from ...utils import refresh_functions

    advice = (user_advice or "").strip()
    if not advice:
        return "Error: user_advice is required for run_custom_annotation."

    config, current_func_addr, current_func_name = _prepare_chatbot_annotation_context()
    if not config:
        return "Failed to start custom annotation: invalid config or no function at cursor."

    async def _chatbot_custom_annotation_thread():
        try:
            success = await run_custom_prompt_analysis(config, current_func_name, current_func_addr, advice)
            if not success:
                print("[AETHER] [Chatbot] Custom annotation failed.")
                return
            refresh_functions(fallback_func_addr=current_func_addr, log_prefix="[AETHER] [Chatbot]")
        except Exception as e:
            print(f"[AETHER] [Chatbot] Error running custom annotation: {e}")
            import traceback
            traceback.print_exc()

    task = schedule_ui_task(_chatbot_custom_annotation_thread())
    if task is None:
        return "Failed to queue custom annotation task."
    return f"Queued custom annotation for '{current_func_name}' at {current_func_addr}."

def save_summary(state: AgentState, summary: str) -> str:
    """Saves the conversation summary."""
    user_prompt = state.conversation_history[0]
    recent_context = []
    last_exchange = state.conversation_history
    if len(state.conversation_history) > 2:
        last_exchange = state.conversation_history[-2:]

    state.conversation_history.clear()
    state.conversation_history.append(user_prompt)

    compressed_context = (
        "--- AGENT STATE START ---\n"
        f"{str(state)}\n"
        "--- AGENT STATE END ---\n\n"
        "### CONVERSATION SUMMARY\n"
        f"{summary}\n\n"
        "The previous history has been compressed. The conversation resumes below."
    )

    state.conversation_history.append({
        "role": "system", 
        "content": compressed_context
    })

    state.conversation_history.extend(last_exchange)

    return "Conversation history summarized."

def generate_python_script(state: AgentState, func_name, objective) -> str:
    print(f"[GENERATE_PYTHON_SCRIPT] Generating script for {func_name}")
    print(f"[GENERATE_PYTHON_SCRIPT] Objective: {objective}")

    ida_kernwin.execute_sync(
        lambda: DeobfuscateHandler.generate_script_and_window(prompt="", target_func=func_name, is_chatbot_tool_call=True),
        ida_kernwin.MFF_WRITE  # MFF_WRITE waits for completion
    )
    
    return "Opened Script Generation Window"
# --- Function Index Tools ---

def search_indexed_functions(state: AgentState, query: str, max_results: str = "10") -> str:
    """Search the function index by keyword across names, summaries, tags, APIs, and constants."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if not idx.is_usable_for_queries():
        return "Error: No usable function index exists. Run 'Index Binary' from the AETHER menu first."
    try:
        limit = int(max_results)
    except ValueError:
        limit = 10
    limit = max(1, min(limit, 50))
    matches = [e for e in idx.entries_by_address.values() if e.matches_keyword(query)]
    if not matches:
        return f"No indexed functions match '{query}'."
    matches = matches[:limit]
    lines = [f"Found {len(matches)} match(es) for '{query}':"]
    for e in matches:
        importance = e.get_importance_level() or "N/A"
        cats = ", ".join(sorted(e.get_functional_categories())) or "none"
        lines.append(f"  - {e.name} ({e.address}) [{importance}] tags=[{cats}] :: {e.summary}")
    result = "\n".join(lines)
    print(f"[Agent] Tool Result: search_indexed_functions -> {len(matches)} matches")
    return result


def get_function_index_summary(state: AgentState) -> str:
    """Get a high-level summary of the function index: counts, tag distribution, and top functions."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if idx.is_empty():
        return "No function index exists for this binary. Run 'Index Binary' from the AETHER menu first."
    total = idx.size()
    importance_dist: dict[str, int] = {}
    tag_dist: dict[str, int] = {}
    for e in idx.entries_by_address.values():
        imp = e.get_importance_level() or "UNTAGGED"
        importance_dist[imp] = importance_dist.get(imp, 0) + 1
        for cat in e.get_functional_categories():
            tag_dist[cat] = tag_dist.get(cat, 0) + 1
    lines = [
        f"Index: {idx.program_name or 'unknown'} | State: {idx.indexing_state} | Indexed: {total}/{idx.total_function_count} functions",
        "",
        "Importance distribution:",
    ]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL", "UNTAGGED"):
        count = importance_dist.get(level, 0)
        if count:
            lines.append(f"  {level}: {count}")
    lines.append("")
    lines.append("Top tags:")
    for tag, count in sorted(tag_dist.items(), key=lambda x: x[1], reverse=True)[:15]:
        lines.append(f"  {tag}: {count}")
    result = "\n".join(lines)
    print(f"[Agent] Tool Result: get_function_index_summary -> {total} entries")
    return result


def get_indexed_function_detail(state: AgentState, function_name: str) -> str:
    """Get full indexed details for a function by name or address."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if not idx.is_usable_for_queries():
        return "Error: No usable function index exists. Run 'Index Binary' from the AETHER menu first."
    entry = idx.get_entry_by_name(function_name)
    if entry is None:
        entry = idx.get_entry_by_address(function_name)
    if entry is None:
        return f"Function '{function_name}' not found in the index."
    lines = [
        f"Name: {entry.name}",
        f"Address: {entry.address}",
        f"Importance: {entry.get_importance_level() or 'N/A'}",
        f"Tags: {', '.join(sorted(entry.tags)) or 'none'}",
        f"Summary: {entry.summary}",
    ]
    if entry.callee_functions:
        lines.append(f"Callees: {', '.join(entry.callee_functions)}")
    if entry.key_operations:
        lines.append(f"Key operations: {', '.join(entry.key_operations)}")
    if entry.key_constants:
        lines.append(f"Key constants: {', '.join(entry.key_constants)}")
    if entry.called_apis:
        lines.append(f"Called APIs: {', '.join(entry.called_apis)}")
    result = "\n".join(lines)
    print(f"[Agent] Tool Result: get_indexed_function_detail for '{function_name}'")
    return result


def ask_index_agent(state: AgentState, query: str) -> str:
    """Ask the IndexAgent to formulate a Briefing Packet of starting candidates based on a natural language query."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if not idx.is_usable_for_queries():
        return "Error: No usable function index exists. Run 'Index Binary' from the AETHER menu first."
    
    print(f"[Agent] Interrogating IndexAgent for query: {query}...")
    from .index_agent import IndexAgent
    agent = IndexAgent()
    result = agent.search_index(query)
    print(f"[Agent] IndexAgent returned a Briefing Packet.")
    return result


# --- Function Index Tools ---

def search_indexed_functions(state: AgentState, query: str, max_results: str = "10") -> str:
    """Search the function index by keyword across names, summaries, tags, APIs, and constants."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if not idx.is_usable_for_queries():
        return "Error: No usable function index exists. Run 'Index Binary' from the AETHER menu first."
    try:
        limit = int(max_results)
    except ValueError:
        limit = 10
    limit = max(1, min(limit, 50))
    matches = [e for e in idx.entries_by_address.values() if e.matches_keyword(query)]
    if not matches:
        return f"No indexed functions match '{query}'."
    matches = matches[:limit]
    lines = [f"Found {len(matches)} match(es) for '{query}':"]
    for e in matches:
        importance = e.get_importance_level() or "N/A"
        cats = ", ".join(sorted(e.get_functional_categories())) or "none"
        lines.append(f"  - {e.name} ({e.address}) [{importance}] tags=[{cats}] :: {e.summary}")
    result = "\n".join(lines)
    print(f"[Agent] Tool Result: search_indexed_functions -> {len(matches)} matches")
    return result


def get_function_index_summary(state: AgentState) -> str:
    """Get a high-level summary of the function index: counts, tag distribution, and top functions."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if idx.is_empty():
        return "No function index exists for this binary. Run 'Index Binary' from the AETHER menu first."
    total = idx.size()
    importance_dist: dict[str, int] = {}
    tag_dist: dict[str, int] = {}
    for e in idx.entries_by_address.values():
        imp = e.get_importance_level() or "UNTAGGED"
        importance_dist[imp] = importance_dist.get(imp, 0) + 1
        for cat in e.get_functional_categories():
            tag_dist[cat] = tag_dist.get(cat, 0) + 1
    lines = [
        f"Index: {idx.program_name or 'unknown'} | State: {idx.indexing_state} | Indexed: {total}/{idx.total_function_count} functions",
        "",
        "Importance distribution:",
    ]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL", "UNTAGGED"):
        count = importance_dist.get(level, 0)
        if count:
            lines.append(f"  {level}: {count}")
    lines.append("")
    lines.append("Top tags:")
    for tag, count in sorted(tag_dist.items(), key=lambda x: x[1], reverse=True)[:15]:
        lines.append(f"  {tag}: {count}")
    result = "\n".join(lines)
    print(f"[Agent] Tool Result: get_function_index_summary -> {total} entries")
    return result


def get_indexed_function_detail(state: AgentState, function_name: str) -> str:
    """Get full indexed details for a function by name or address."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if not idx.is_usable_for_queries():
        return "Error: No usable function index exists. Run 'Index Binary' from the AETHER menu first."
    entry = idx.get_entry_by_name(function_name)
    if entry is None:
        entry = idx.get_entry_by_address(function_name)
    if entry is None:
        return f"Function '{function_name}' not found in the index."
    lines = [
        f"Name: {entry.name}",
        f"Address: {entry.address}",
        f"Importance: {entry.get_importance_level() or 'N/A'}",
        f"Tags: {', '.join(sorted(entry.tags)) or 'none'}",
        f"Summary: {entry.summary}",
    ]
    if entry.callee_functions:
        lines.append(f"Callees: {', '.join(entry.callee_functions)}")
    if entry.key_operations:
        lines.append(f"Key operations: {', '.join(entry.key_operations)}")
    if entry.key_constants:
        lines.append(f"Key constants: {', '.join(entry.key_constants)}")
    if entry.called_apis:
        lines.append(f"Called APIs: {', '.join(entry.called_apis)}")
    result = "\n".join(lines)
    print(f"[Agent] Tool Result: get_indexed_function_detail for '{function_name}'")
    return result


def ask_index_agent(state: AgentState, query: str) -> str:
    """Ask the IndexAgent to formulate a Briefing Packet of starting candidates based on a natural language query."""
    if not _HAS_INDEXING:
        return "Error: Indexing module is not available."
    idx = FunctionIndexManager.get_index()
    if not idx.is_usable_for_queries():
        return "Error: No usable function index exists. Run 'Index Binary' from the AETHER menu first."
    
    print(f"[Agent] Interrogating IndexAgent for query: {query}...")
    from .index_agent import IndexAgent
    agent = IndexAgent()
    result = agent.search_index(query)
    print(f"[Agent] IndexAgent returned a Briefing Packet.")
    return result


# --- Tool Registry ---

TOOL_REGISTRY = {
    ToolNames.ADD_ACTION_PLAN: add_action_plan,
    ToolNames.ADD_TASK_TO_PLAN: add_task_to_plan,
    ToolNames.UPDATE_TASK: update_task,
    ToolNames.REMOVE_TASK_FROM_PLAN: remove_task_from_plan,
    ToolNames.REMOVE_ACTION_PLAN: remove_action_plan,
    ToolNames.ADD_SHORT_TERM_MEMORY: add_short_term_memory,
    ToolNames.REMOVE_SHORT_TERM_MEMORY: remove_short_term_memory,
    ToolNames.LIST_FUNCTIONS: list_functions,
    ToolNames.GET_FUNCTION_PSEUDOCODE: get_function_pseudocode,
    ToolNames.ADD_TO_FUNCTION_LIST: add_to_function_list,
    ToolNames.REMOVE_FROM_FUNCTION_LIST: remove_from_function_list,
    ToolNames.GET_DATA_AT_ADDRESS: get_data_at_address,
    ToolNames.GET_XREFS_TO: get_xrefs_to,
    ToolNames.RUN_FASTLOOK_ANNOTATION: run_fastlook_annotation,
    ToolNames.RUN_CUSTOM_ANNOTATION: run_custom_annotation,
    ToolNames.SAVE_SUMMARY: save_summary,
    ToolNames.GENERATE_PYTHON_SCRIPT: generate_python_script,
    ToolNames.SEARCH_INDEXED_FUNCTIONS: search_indexed_functions,
    ToolNames.GET_FUNCTION_INDEX_SUMMARY: get_function_index_summary,
    ToolNames.GET_INDEXED_FUNCTION_DETAIL: get_indexed_function_detail,
    ToolNames.ASK_INDEX_AGENT: ask_index_agent
}
