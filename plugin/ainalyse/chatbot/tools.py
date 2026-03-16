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

from .core import AgentState, TaskStatus

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
    SAVE_SUMMARY = "save_summary"

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
    ToolNames.SAVE_SUMMARY: save_summary,
}
