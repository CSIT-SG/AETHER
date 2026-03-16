from __future__ import annotations

from enum import StrEnum
from typing import Any, Dict, List, Optional

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name

# --- Global Constants ---
MAX_FUNCTION_LIST_SIZE = 10

class TaskStatus(StrEnum):
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    FAILED = "Failed"

class Task:
    """Represents a single, atomic task."""
    def __init__(self, description: str):
        self.description = description
        self.status: TaskStatus = TaskStatus.NOT_STARTED

class ActionPlan:
    """Represents a complex, multi-step plan with a description and a list of tasks."""
    def __init__(self, description: str):
        self.description = description
        self.tasks: List[Task] = []

    def add_task(self, task: Task, index: Optional[int] = None):
        """Adds a task to the plan, optionally at a specific index."""
        if index is None or index >= len(self.tasks):
            self.tasks.append(task)
        else:
            self.tasks.insert(index, task)

    def __str__(self):
        task_lines = []
        for i, task in enumerate(self.tasks):
            status_map = {
                TaskStatus.NOT_STARTED: "Not Started",
                TaskStatus.IN_PROGRESS: "In Progress",
                TaskStatus.COMPLETED: "Completed",
                TaskStatus.FAILED: "Failed",
            }
            status = status_map.get(task.status, "[?]")
            task_lines.append(f"  '{status}' {task.description} (ID: {i})")
        
        tasks_str = "\n".join(task_lines)
        return f"{self.description}\n{tasks_str}"


class AgentState:
    """
    Represents the current state of the chatbot agent's memory and plans.
    It also contains all the methods to manage and modify the state.
    """
    def __init__(self):
        """Initializes the agent's state."""
        self.short_term_mem: Dict[str, Any] = {}
        self.action_plans: List[ActionPlan] = []
        self.function_list: List[int] = []  # Store addresses (int) instead of names
        self.last_action: Optional[str] = None
        self.last_result: Optional[Any] = None
        self.conversation_history: List[Dict[str, str]] = []

    # --- Private Helper Methods ---

    def _get_plan(self, plan_index: int) -> Optional[ActionPlan]:
        if 0 <= plan_index < len(self.action_plans):
            return self.action_plans[plan_index]
        print(f"[Agent] Error: ActionPlan with index {plan_index} not found.")
        return None

    def _get_task(self, plan_index: int, task_index: int) -> Optional[Task]:
        """Finds a task by its plan and task index."""
        plan = self._get_plan(plan_index)
        if plan and 0 <= task_index < len(plan.tasks):
            return plan.tasks[task_index]
        print(f"[Agent] Error: Task with index {task_index} not found in plan {plan_index}.")
        return None

    # --- Public State Management Methods ---

    def add_short_term_memory(self, key: str, value: Any):
        """Adds or updates a key-value pair in the agent's short-term memory."""
        self.short_term_mem[key] = value
        print(f"[Agent] Set memory key '{key}' to '{str(value)[:100]}...'.")

    def remove_short_term_memory(self, key: Optional[str] = None, index: Optional[int] = None):
        """Removes a memory entry by its key or its current numerical index."""
        if key is None and index is None:
            print("[Agent] Error: Must provide either a key or an index to remove memory.")
            return

        key_to_remove = key
        if index is not None:
            if 0 <= index < len(self.short_term_mem):
                key_to_remove = list(self.short_term_mem.keys())[index]
            else:
                print(f"[Agent] Error: Memory with index {index} not found for removal.")
                return
        
        if key_to_remove and key_to_remove in self.short_term_mem:
            del self.short_term_mem[key_to_remove]
            print(f"[Agent] Removed memory key '{key_to_remove}'.")
        else:
            print(f"[Agent] Error: Memory with key '{key_to_remove}' not found for removal.")

    def add_action_plan(self, description: str, task_descriptions: List[str], index: Optional[int] = None):
        """Creates and adds a new action plan to the agent's list of plans."""
        plan = ActionPlan(description)
        for desc in task_descriptions:
            plan.add_task(Task(description=desc))
        
        if index is None or index >= len(self.action_plans):
            self.action_plans.append(plan)
            print(f"[Agent] Appended action plan: {description}")
        else:
            self.action_plans.insert(index, plan)
            print(f"[Agent] Inserted action plan at index {index}: {description}")

    def add_task_to_plan(self, plan_index: int, description: str, index: Optional[int] = None):
        """Adds a task to a specific action plan."""
        plan = self._get_plan(plan_index)
        if not plan:
            return

        new_task = Task(description)
        plan.add_task(new_task, index)
        print(f"[Agent] Added task to plan {plan_index}: {description}")

    def update_task(self, plan_index: int, task_index: int, status: TaskStatus):
        """Updates the status of a task in a specific action plan."""
        task = self._get_task(plan_index, task_index)
        if task:
            task.status = status
            print(f"[Agent] Marked task '{task.description}' in plan {plan_index} as {status.value}.")

    def remove_task_from_plan(self, plan_index: int, task_index: int):
        """Removes a task from a specific action plan using its index."""
        plan = self._get_plan(plan_index)
        if plan and 0 <= task_index < len(plan.tasks):
            removed_task_desc = plan.tasks[task_index].description
            del plan.tasks[task_index]
            print(f"[Agent] Removed task '{removed_task_desc}' (ID: {task_index}) from plan {plan_index}.")
        else:
            print(f"[Agent] Error: Task with index {task_index} not found for removal in plan {plan_index}.")

    def remove_action_plan(self, plan_index: int):
        """Removes a specific action plan from the agent's state."""
        if 0 <= plan_index < len(self.action_plans):
            removed_plan_desc = self.action_plans[plan_index].description
            del self.action_plans[plan_index]
            print(f"[Agent] Removed action plan at index {plan_index}: '{removed_plan_desc}'.")
        else:
            print(f"[Agent] Error: ActionPlan with index {plan_index} not found for removal.")

    def add_to_function_list(self, function_name: str):
        """Adds a function to the analysis list if there is space."""
        msg_container = {'msg': None}
        def _add_to_function_list_sync():
            func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR,function_name)
            if func_ea == ida_idaapi.BADADDR:
                print(f"[Agent] Error: Function '{function_name}' not found.")
                msg_container['msg'] = f"Error: Function '{function_name}' not found."
                return None

            if func_ea in self.function_list:
                print(f"[Agent] Function '{function_name}' is already in the analysis list.")
                msg_container['msg'] =  f"'{function_name}' is already in the analysis list."
                return None

            if len(self.function_list) >= MAX_FUNCTION_LIST_SIZE:
                print(f"[Agent] Error: Cannot add function. Analysis list is full (max {MAX_FUNCTION_LIST_SIZE}).")
                msg_container['msg'] = f"Function List is full (max {MAX_FUNCTION_LIST_SIZE})"
                return None

            self.function_list.append(func_ea)
            return True
        ida_kernwin.execute_sync(_add_to_function_list_sync, ida_kernwin.MFF_READ)
        if msg_container['msg']:
            return msg_container['msg']
        print(f"[Agent] Added '{function_name}' to analysis list.")
        return f"Added '{function_name}' to analysis list."

    def remove_from_function_list(self, function_name: str):
        """Removes a function from the analysis list."""
        func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR,function_name)
        if func_ea == ida_idaapi.BADADDR:
            print(f"[Agent] Error: Function '{function_name}' not found.")
            return
        try:
            self.function_list.remove(func_ea)
            print(f"[Agent] Removed '{function_name}' from analysis list.")
        except ValueError:
            print(f"[Agent] Error: Function '{function_name}' not found in analysis list.")

    def clear_all_plans(self):
        """Removes all action plans from the agent's state."""
        self.action_plans = []
        print("[Agent] All action plans removed.")

    def clear_memory(self):
        """Clears the agent's state, including memory, plans, and function list."""
        self.short_term_mem = {}
        self.action_plans = []
        self.function_list = []
        self.last_action = None
        self.last_result = None

    def __str__(self) -> str:
        """Provides a clean, human-readable string of the agent's state."""
        # Memory Formatting
        if self.short_term_mem:
            mem_lines = [f"  - {k}: {str(v)[:50]}" for k, v in self.short_term_mem.items()]
            memory_str = "\n".join(mem_lines)
        else:
            memory_str = "  (empty)"
        
        if self.action_plans:
            plan_list = []
            for i, plan in enumerate(self.action_plans):
                plan_list.append(f"--- Plan {i} ---\n{str(plan)}")
            plan_str = "\n".join(plan_list)
        else:
            plan_str = "No active plans."
        
        # Function List Formatting (using IDA API safely)
        try:
            func_names = [ida_funcs.get_func_name(ea) for ea in self.function_list]
            function_str = f"[{', '.join(func_names)}]" if func_names else "[]"
        except:
            function_str = "[]"

        return (
            f"AgentState:\n"
            f"- Short Term Memory:\n{memory_str}\n"
            f"- Action Plans:\n{plan_str}\n"
            f"- Active Functions: {function_str}\n"
        )
