from __future__ import annotations

import time
from enum import StrEnum
import ast
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ..chatbot_agent import ChatbotAgentState


try:
    from ainalyse.qt_shim import QtWidgets
    QApplication = QtWidgets.QApplication
except Exception:  # pragma: no cover - unavailable in unit tests
    QApplication = None

try:
    from ainalyse.indexing import FunctionIndexManager
except Exception:  # pragma: no cover - unavailable in unit tests
    FunctionIndexManager = None


class ToolNames(StrEnum):
    ADD_ACTION_PLAN = "add_action_plan"
    ADD_TASK_TO_PLAN = "add_task_to_plan"
    UPDATE_TASK = "update_task"
    REMOVE_TASK_FROM_PLAN = "remove_task_from_plan"
    REMOVE_ACTION_PLAN = "remove_action_plan"
    ADD_MEMORY = "add_memory"
    REMOVE_MEMORY = "remove_memory"
    SEARCH_MEMORY = "search_memory"
    LIST_FUNCTIONS = "list_functions"
    GET_FUNCTION_PSEUDOCODE = "get_function_pseudocode"
    ADD_TO_FUNCTION_LIST = "add_to_function_list"
    REMOVE_FROM_FUNCTION_LIST = "remove_from_function_list"
    GET_DATA_AT_ADDRESS = "get_data_at_address"
    GET_XREFS_TO = "get_xrefs_to"
    ANNOTATE_FUNCTION = "annotate_function"
    SAVE_SUMMARY = "save_summary"
    SEARCH_INDEXED_FUNCTIONS = "search_indexed_functions"
    GET_FUNCTION_INDEX_SUMMARY = "get_function_index_summary"
    GET_INDEXED_FUNCTION_DETAIL = "get_indexed_function_detail"
    ASK_INDEX_AGENT = "ask_index_agent"
    GENERATE_PYTHON_SCRIPT = "generate_python_script"
    DELEGATE_STRUCT_TASK = "delegate_struct_task"


CHATBOT_TOOL_NAMES = ToolNames


CHATBOT_TOOL_SPECS = {
    ToolNames.ADD_ACTION_PLAN: {
        "description": "Create and insert a new action plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "plan_index": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["plan_index", "description"],
        },
        "arg_order": ["plan_index", "description"],
    },
    ToolNames.ADD_TASK_TO_PLAN: {
        "description": "Add a task to an existing action plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "plan_index": {"type": "string"},
                "task_index": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["plan_index", "task_index", "description"],
        },
        "arg_order": ["plan_index", "task_index", "description"],
    },
    ToolNames.UPDATE_TASK: {
        "description": "Update the status of a task in an action plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "plan_index": {"type": "string"},
                "task_index": {"type": "string"},
                "status": {"type": "string"},
            },
            "required": ["plan_index", "task_index", "status"],
        },
        "arg_order": ["plan_index", "task_index", "status"],
    },
    ToolNames.REMOVE_TASK_FROM_PLAN: {
        "description": "Remove a task from an action plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "plan_index": {"type": "string"},
                "task_index": {"type": "string"},
            },
            "required": ["plan_index", "task_index"],
        },
        "arg_order": ["plan_index", "task_index"],
    },
    ToolNames.REMOVE_ACTION_PLAN: {
        "description": "Remove a completed or abandoned action plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "plan_index": {"type": "string"},
            },
            "required": ["plan_index"],
        },
        "arg_order": ["plan_index"],
    },
    ToolNames.ADD_MEMORY: {
        "description": "Store a memory item in the chatbot runtime memory store for later retrieval and prompt context.",
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Stable lookup key for the memory."},
                "value": {"type": "string", "description": "Concise memory content to preserve."},
                "category": {"type": "string", "description": "Memory category, e.g. finding, decision, user_preference, analysis_context."},
                "priority": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "description": "Retrieval and display priority."},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional tags for filtering and retrieval."},
            },
            "required": ["key", "value", "category"],
        },
        "arg_order": ["key", "value", "category", "priority", "tags"],
    },
    ToolNames.REMOVE_MEMORY: {
        "description": "Remove a memory item from the chatbot runtime memory store by memory_id, key, or display index.",
        "parameters": {
            "type": "object",
            "properties": {
                "memory_id": {"type": "string"},
                "key": {"type": "string"},
                "index": {"type": "string"},
            },
        },
        "arg_order": ["memory_id", "key", "index"],
    },
    ToolNames.SEARCH_MEMORY: {
        "description": "Search the chatbot memory store for facts, findings, decisions, and prior analysis context relevant to a query.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Natural-language memory search query."},
                "top_k": {"type": "string", "description": "Maximum number of memory results to return."},
            },
            "required": ["query"],
        },
        "arg_order": ["query", "top_k"],
    },
    ToolNames.LIST_FUNCTIONS: {
        "description": "List available functions in the current binary. You can provide an optional regex pattern to filter by name. The results are limited to prevent overflow.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Optional regex pattern to filter function names (e.g. '.*main.*')."},
                "limit": {"type": "string", "description": "Optional maximum number of functions to return (default 500)."}
            }
        },
        "arg_order": ["pattern", "limit"],
    },
    ToolNames.GET_FUNCTION_PSEUDOCODE: {
        "description": "Retrieve Hex-Rays pseudocode for a function by function name.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
            },
            "required": ["function_name"],
        },
        "arg_order": ["function_name"],
    },
    ToolNames.ADD_TO_FUNCTION_LIST: {
        "description": "Add a function to the active analysis function list.",
        "parameters": {
            "type": "object",
            "properties": {
                "func_name": {"type": "string"},
            },
            "required": ["func_name"],
        },
        "arg_order": ["func_name"],
    },
    ToolNames.REMOVE_FROM_FUNCTION_LIST: {
        "description": "Remove a function from the active analysis function list.",
        "parameters": {
            "type": "object",
            "properties": {
                "func_name": {"type": "string"},
            },
            "required": ["func_name"],
        },
        "arg_order": ["func_name"],
    },
    ToolNames.GET_DATA_AT_ADDRESS: {
        "description": "Read bytes and any string at a function name or address.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {"type": "string"},
                "count": {"type": "string"},
            },
            "required": ["location"],
        },
        "arg_order": ["location", "count"],
    },
    ToolNames.GET_XREFS_TO: {
        "description": "List cross references to a function name or address.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {"type": "string"},
            },
            "required": ["location"],
        },
        "arg_order": ["location"],
    },
    ToolNames.ANNOTATE_FUNCTION: {
        "description": "Perform an automated analysis of the current IDA function to add comments and renames. Optional advice can guide the focus.",
        "parameters": {
            "type": "object",
            "properties": {
                "advice": {"type": "string", "description": "Optional natural-language guidance (e.g., 'Focus on crypto constants')."},
            },
        },
        "arg_order": ["advice"],
    },
    ToolNames.SAVE_SUMMARY: {
        "description": "Compress the conversation history into a summary block.",
        "parameters": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
            },
            "required": ["summary"],
        },
        "arg_order": ["summary"],
    },
    ToolNames.SEARCH_INDEXED_FUNCTIONS: {
        "description": "Search the function index by keyword across names, summaries, tags, APIs, and constants.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "max_results": {"type": "string"},
            },
            "required": ["query"],
        },
        "arg_order": ["query", "max_results"],
    },
    ToolNames.GET_FUNCTION_INDEX_SUMMARY: {
        "description": "Retrieve a high-level overview of the function index, counts, and tag distribution.",
        "parameters": {"type": "object", "properties": {}},
        "arg_order": [],
    },
    ToolNames.GET_INDEXED_FUNCTION_DETAIL: {
        "description": "Retrieve indexed details for a specific function by name or address.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
            },
            "required": ["function_name"],
        },
        "arg_order": ["function_name"],
    },
    ToolNames.ASK_INDEX_AGENT: {
        "description": "Ask the IndexAgent to find likely functions for a high-level natural-language query.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
            "required": ["query"],
        },
        "arg_order": ["query"],
    },
    ToolNames.GENERATE_PYTHON_SCRIPT: {
        "description": "Open the Python script generation window for a function and objective.",
        "parameters": {
            "type": "object",
            "properties": {
                "func_name": {"type": "string"},
                "objective": {"type": "string"},
            },
            "required": ["func_name", "objective"],
        },
        "arg_order": ["func_name", "objective"],
    },
    ToolNames.DELEGATE_STRUCT_TASK: {
        "description": "Communicate with the StructAgent specialist. StructAgent analyzes relevant function context, checks/reuses existing structs, proposes or applies struct/field updates using struct tools, and asks for missing evidence when needed. Use this tool to delegate struct-focused work and receive StructAgent's direct reply. In the free-form message, if function pseudocode does not show an existing struct, include a suggested struct name and explicitly identify the target variable the struct should be created/applied for.",
        "parameters": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "relevant_functions": {"type": "array", "items": {"type": "string"}},
                "context_description": {"type": "string"},
            },
            "required": ["message", "relevant_functions"],
        },
        "arg_order": ["message", "relevant_functions", "context_description"],
    },
}


class ChatbotToolbox:
    _index_locked_tools = {
        ToolNames.SEARCH_INDEXED_FUNCTIONS,
        ToolNames.GET_FUNCTION_INDEX_SUMMARY,
        ToolNames.GET_INDEXED_FUNCTION_DETAIL,
        ToolNames.ASK_INDEX_AGENT,
    }

    def __init__(self, state: "ChatbotAgentState"):
        from ..chatbot_agent import TaskStatus

        self._task_status = TaskStatus
        self.state = state
        self.registry: dict[ToolNames, Callable[..., str]] = {
            ToolNames.ADD_ACTION_PLAN: self.add_action_plan,
            ToolNames.ADD_TASK_TO_PLAN: self.add_task_to_plan,
            ToolNames.UPDATE_TASK: self.update_task,
            ToolNames.REMOVE_TASK_FROM_PLAN: self.remove_task_from_plan,
            ToolNames.REMOVE_ACTION_PLAN: self.remove_action_plan,
            ToolNames.ADD_MEMORY: self.add_memory,
            ToolNames.REMOVE_MEMORY: self.remove_memory,
            ToolNames.SEARCH_MEMORY: self.search_memory,
            ToolNames.LIST_FUNCTIONS: self.list_functions,
            ToolNames.GET_FUNCTION_PSEUDOCODE: self.get_function_pseudocode,
            ToolNames.ADD_TO_FUNCTION_LIST: self.add_to_function_list,
            ToolNames.REMOVE_FROM_FUNCTION_LIST: self.remove_from_function_list,
            ToolNames.GET_DATA_AT_ADDRESS: self.get_data_at_address,
            ToolNames.GET_XREFS_TO: self.get_xrefs_to,
            ToolNames.ANNOTATE_FUNCTION: self.annotate_function,
            ToolNames.SAVE_SUMMARY: self.save_summary,
            ToolNames.SEARCH_INDEXED_FUNCTIONS: self.search_indexed_functions,
            ToolNames.GET_FUNCTION_INDEX_SUMMARY: self.get_function_index_summary,
            ToolNames.GET_INDEXED_FUNCTION_DETAIL: self.get_indexed_function_detail,
            ToolNames.ASK_INDEX_AGENT: self.ask_index_agent,
            ToolNames.GENERATE_PYTHON_SCRIPT: self.generate_python_script,
            ToolNames.DELEGATE_STRUCT_TASK: self.delegate_struct_task,
        }

    def execute(self, tool_name: str | ToolNames, *args: str) -> str:
        normalized = ToolNames(tool_name)
        return self.registry[normalized](*args)

    def execute_named(self, tool_name: str | ToolNames, arguments: dict[str, object] | None = None) -> str:
        normalized = ToolNames(tool_name)
        arguments = arguments or {}
        spec = CHATBOT_TOOL_SPECS[normalized]
        args = ["" if arguments.get(name) is None else arguments.get(name) for name in spec["arg_order"]]
        return self.execute(normalized, *args)

    def get_tool_definitions(self, enabled_tools: set[str] | None = None) -> list[dict[str, object]]:
        definitions: list[dict[str, object]] = []

        index_available = False
        if FunctionIndexManager is not None:
            idx = FunctionIndexManager.get_index()
            if idx and idx.is_usable_for_queries():
                index_available = True

        for tool_name, spec in CHATBOT_TOOL_SPECS.items():
            if enabled_tools is not None and tool_name.value not in enabled_tools:
                continue

            if tool_name in self._index_locked_tools and not index_available:
                continue

            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool_name.value,
                        "description": spec["description"],
                        "parameters": spec["parameters"],
                    },
                }
            )
        return definitions

    def add_action_plan(self, plan_index: str, description: str) -> str:
        try:
            self.state.add_action_plan(description, [], int(plan_index))
            return f"Action plan {plan_index} added: {description}"
        except ValueError:
            return f"Error: Invalid plan_index '{plan_index}'. Must be an integer."

    def add_task_to_plan(self, plan_index: str, task_index: str, description: str) -> str:
        try:
            self.state.add_task_to_plan(int(plan_index), description, int(task_index))
            return f"Task {task_index} added to plan {plan_index}: {description}"
        except ValueError:
            return f"Error: Invalid plan_index '{plan_index}' or task_index '{task_index}'. Must be an integer."
        except IndexError as exc:
            return f"Error: {exc}"

    def update_task(self, plan_index: str, task_index: str, status: str) -> str:
        try:
            self.state.update_task(int(plan_index), int(task_index), self._task_status(status))
            return f"Task {task_index} in plan {plan_index} updated to {status}"
        except ValueError:
            return f"Error: Invalid status '{status}' or index. plan_index and task_index must be integers."
        except IndexError as exc:
            return f"Error: {exc}"

    def remove_task_from_plan(self, plan_index: str, task_index: str) -> str:
        try:
            self.state.remove_task_from_plan(int(plan_index), int(task_index))
            return f"Task {task_index} removed from plan {plan_index}"
        except ValueError:
            return f"Error: Invalid plan_index '{plan_index}' or task_index '{task_index}'. Must be an integer."
        except IndexError as exc:
            return f"Error: {exc}"

    def remove_action_plan(self, plan_index: str) -> str:
        try:
            self.state.remove_action_plan(int(plan_index))
            return f"Action plan {plan_index} removed"
        except ValueError:
            return f"Error: Invalid plan_index '{plan_index}'. Must be an integer."
        except IndexError as exc:
            return f"Error: {exc}"

    def _coerce_tags(self, tags: Any) -> list[str]:
        if tags in (None, ""):
            return []
        if isinstance(tags, list):
            return [str(tag) for tag in tags if str(tag)]
        if isinstance(tags, tuple):
            return [str(tag) for tag in tags if str(tag)]
        if isinstance(tags, str):
            stripped = tags.strip()
            if not stripped:
                return []
            try:
                parsed = ast.literal_eval(stripped)
            except (SyntaxError, ValueError):
                return [tag.strip() for tag in stripped.split(",") if tag.strip()]
            if isinstance(parsed, (list, tuple)):
                return [str(tag) for tag in parsed if str(tag)]
        return [str(tags)]

    def add_memory(
        self,
        key: str,
        value: str,
        category: str = "chatbot_short_term",
        priority: str = "MEDIUM",
        tags: Any = None,
    ) -> str:
        category = category or "chatbot_short_term"
        priority = priority or "MEDIUM"
        parsed_tags = self._coerce_tags(tags) or ["short_term"]
        self.state.add_memory(key, value, category=category, priority=priority, tags=parsed_tags)
        return f"Memory stored successfully (Key: {key}, Category: {category}, Priority: {priority.upper()})"

    def remove_memory(
        self,
        memory_id: str | None = None,
        key: str | None = None,
        index: str | None = None,
    ) -> str:
        try:
            memory_id = memory_id or None
            key = key or None
            index = index or None
            self.state.remove_memory(
                memory_id=memory_id,
                key=key,
                index=int(index) if index is not None else None,
            )
            if memory_id is not None:
                return f"Memory with id '{memory_id}' removed"
            if index is not None:
                return f"Memory at index {index} removed"
            return f"Memory with key '{key}' removed"
        except ValueError as exc:
            return f"Error: {exc}"
        except (KeyError, IndexError) as exc:
            return f"Error: {exc}"

    def search_memory(self, query: str, top_k: str = "5") -> str:
        query = (query or "").strip()
        if not query:
            return "Error: query is required for search_memory."
        try:
            limit = int(top_k or 5)
        except ValueError:
            limit = 5
        limit = max(1, min(limit, 20))
        results = self.state.memory_store.search_memories(query, top_k=limit)
        if not results:
            return f"No memory results found for '{query}'."

        lines = [f"Found {len(results)} memory result(s) for '{query}':"]
        for index, result in enumerate(results, 1):
            memory = getattr(result, "memory", result)
            score = getattr(result, "relevance_score", None)
            reason = getattr(result, "reason", "")
            category = getattr(memory, "category", "?")
            key = getattr(memory, "key", None)
            content = memory.get_display_content() if hasattr(memory, "get_display_content") else str(memory)
            prefix = f"  {index}. [{category}]"
            if score is not None:
                prefix += f" score={score:.2f}"
            if key:
                prefix += f" key={key}"
            lines.append(f"{prefix}: {content}")
            if reason:
                lines.append(f"     reason: {reason}")
        return "\n".join(lines)

    def add_to_function_list(self, func_name: str) -> str:
        return self.state.add_to_function_list(func_name)

    def remove_from_function_list(self, func_name: str) -> str:
        try:
            self.state.remove_from_function_list(func_name)
            return f"Function '{func_name}' removed from the list"
        except KeyError as exc:
            return f"Error: {exc}"

    def list_functions(self, pattern: str = "", limit: str = "500") -> str:
        try:
            limit_int = int(limit)
        except ValueError:
            limit_int = 500
            
        functions = self.state.bridge.list_functions(pattern, limit_int)
        result = "\n".join(function["name"] for function in functions)
        
        if len(functions) >= limit_int:
            result += f"\n... (Output truncated at {limit_int} functions. Use 'pattern' to narrow down your search.)"
            
        if not result:
            return "No functions matched the pattern."
            
        return result

    def get_function_pseudocode(self, function_name: str) -> str:
        pseudocode = self.state.bridge.get_function_pseudocode(function_name)
        if pseudocode:
            return pseudocode
        return f"Function '{function_name}' not found."

    def get_data_at_address(self, location: str, count: str = "16") -> str:
        try:
            resolved = self.state.bridge.get_data_at_address(location, int(count))
        except ValueError:
            resolved = self.state.bridge.get_data_at_address(location, 16)
        if not resolved or "ea" not in resolved:
            return f"Error: Could not resolve address/name '{location}'."
        lines = [
            f"Data at {resolved['ea']} ({resolved.get('name') or 'unknown'}):",
            f"Symbol hints: {resolved.get('symbol_hints', 'none')}",
            (
                "Item: "
                f"kind={resolved.get('item_kind', 'unknown')}, "
                f"head={resolved.get('item_head')}, "
                f"end={resolved.get('item_end')}, "
                f"size={resolved.get('item_size', 0)}"
            ),
            f"Segment: {resolved.get('segment') or 'unknown'}",
            f"Function context: {resolved.get('function_context', 'outside_function')}",
            f"Disasm: {resolved.get('disasm') or 'N/A'}",
            f"Hex: {resolved.get('bytes', 'No bytes found')}",
            f"String: {resolved.get('string', 'No string found')}",
        ]

        if resolved.get("pointer_candidate"):
            ptr_line = f"Pointer candidate: {resolved['pointer_candidate']}"
            if resolved.get("pointer_target"):
                ptr_line += f" -> {resolved['pointer_target']}"
            lines.append(ptr_line)

        repeat = resolved.get("repeat_pattern")
        if repeat:
            trunc = " (scan capped)" if repeat.get("scan_truncated") else ""
            lines.append(f"Repeat pattern: {repeat.get('byte')} x {repeat.get('length')} until {repeat.get('end_ea')}{trunc}")

        xrefs_preview = resolved.get("xrefs_to") or []
        lines.append(f"Xrefs to this address: total={resolved.get('xrefs_to_total', len(xrefs_preview))}, preview={len(xrefs_preview)}")
        for xref in xrefs_preview:
            lines.append(f"  - {xref.get('from')} in {xref.get('name')} ({xref.get('type')}) [{xref.get('from_context')}]")

        warnings = resolved.get("warnings") or []
        if warnings:
            lines.append(f"Warnings: {len(warnings)}")
            lines.extend(f"  - {warning}" for warning in warnings[:5])
        return "\n".join(lines)

    def get_xrefs_to(self, location: str) -> str:
        xrefs_found = self.state.bridge.get_xrefs_to(location) or []
        target_info = {}
        if xrefs_found and isinstance(xrefs_found[0], dict):
            target_info = xrefs_found[0].get("target") or {}
            if target_info and len(xrefs_found) == 1 and "from" not in xrefs_found[0]:
                summary = [
                    f"Target {target_info.get('name')} @ {target_info.get('ea')} [{target_info.get('context', 'outside_function')}]",
                    f"Target symbol hints: {target_info.get('symbol_hints', 'none')}",
                    f"No cross-references found for '{location}'.",
                ]
                warnings = target_info.get("warnings") or []
                if warnings:
                    summary.append(f"Warnings: {len(warnings)}")
                    summary.extend(f"  - {warning}" for warning in warnings[:5])
                return "\n".join(summary)
        if not xrefs_found:
            return f"No cross-references found for '{location}'."

        output = []
        if target_info:
            output.extend(
                [
                    f"Target {target_info.get('name')} @ {target_info.get('ea')} [{target_info.get('context', 'outside_function')}]",
                    f"Target symbol hints: {target_info.get('symbol_hints', 'none')}",
                ]
            )
        output.append(f"Found {len(xrefs_found)} Xrefs to '{location}':")
        for xref in xrefs_found:
            func_start_flag = "yes" if xref.get("from_is_function_start") else "no"
            output.append(
                f"  - {xref['from']} in {xref['name']} ({xref['type']}) "
                f"[{xref.get('from_context', 'outside_function')}] [from_is_function_start:{func_start_flag}]"
            )
        warnings = target_info.get("warnings") or []
        if warnings:
            output.append(f"Warnings: {len(warnings)}")
            output.extend(f"  - {warning}" for warning in warnings[:5])
        return "\n".join(output)

    def annotate_function(self, advice: str = "") -> str:
        return self.state.bridge.annotate_function(advice)

    def generate_python_script(self, func_name: str, objective: str) -> str:
        return self.state.bridge.generate_python_script(func_name, objective)

    def delegate_struct_task(
        self,
        message: str,
        relevant_functions: Any,
        context_description: str = "",
    ) -> str:
        text = (message or "").strip()
        if not text:
            return "Error: message is required."

        if isinstance(relevant_functions, str):
            funcs = [value.strip() for value in relevant_functions.split(",") if value.strip()]
        elif isinstance(relevant_functions, list):
            funcs = [str(value).strip() for value in relevant_functions if str(value).strip()]
        else:
            funcs = []
        if not funcs:
            return "Error: relevant_functions must include at least one function name."

        context_text = (context_description or "").strip()

        try:
            if self.state.specialist_orchestrator is None:
                return "Error: specialist orchestrator is not configured."
            request_id = self.state.specialist_orchestrator.start_struct_message(
                message=text,
                relevant_functions=funcs,
                context_description=context_text,
            )
        except Exception as exc:
            return f"Error: failed to delegate to StructAgent: {exc}"
        return f"[STRUCT_DELEGATED]{request_id}"

    def save_summary(self, summary: str) -> str:
        manager = self.state.context_manager
        self.state.conversation_history = manager.summarize_conversation_history(
            self.state.conversation_history,
            fallback_summary=summary,
            plan=self.state.plan_manager.active_plan,
        )
        return "Conversation history summarized."

    @staticmethod
    def _index_state_warning(idx) -> str:
        state = (getattr(idx, "indexing_state", "") or "").upper()
        if state and state != "COMPLETED":
            return f"\n\n**Warning:** The index is currently '{state}'. Results may be incomplete."
        return ""

    @classmethod
    def _ensure_index_ready(cls, requesting_tool: ToolNames):
        if FunctionIndexManager is None:
            return None, "Indexing support is unavailable in this environment."

        idx = FunctionIndexManager.get_index()
        if idx and idx.is_usable_for_queries():
            return idx, None

        return None, "No usable function index is available. Please run 'Index Binary' from the AETHER menu first."

    def search_indexed_functions(self, query: str, max_results: str = "10") -> str:
        idx, gate_msg = self._ensure_index_ready(ToolNames.SEARCH_INDEXED_FUNCTIONS)
        if gate_msg:
            return gate_msg

        warning = self._index_state_warning(idx)
        try:
            limit = int(max_results)
        except ValueError:
            limit = 10
        limit = max(1, min(limit, 50))

        matches = [entry for entry in idx.entries_by_address.values() if entry.matches_keyword(query)]
        if not matches:
            return f"No indexed functions match '{query}'.{warning}"

        matches = matches[:limit]
        lines = [f"Found {len(matches)} match(es) for '{query}':"]
        for entry in matches:
            importance = entry.get_importance_level() or "N/A"
            tags = ", ".join(sorted(entry.get_functional_categories())) or "none"
            lines.append(f"  - {entry.name} ({entry.address}) [{importance}] tags=[{tags}] :: {entry.summary}")
        return "\n".join(lines) + warning

    def get_function_index_summary(self) -> str:
        idx, gate_msg = self._ensure_index_ready(ToolNames.GET_FUNCTION_INDEX_SUMMARY)
        if gate_msg:
            return gate_msg

        total = idx.size()
        importance_dist: dict[str, int] = {}
        tag_dist: dict[str, int] = {}
        for entry in idx.entries_by_address.values():
            importance = entry.get_importance_level() or "UNTAGGED"
            importance_dist[importance] = importance_dist.get(importance, 0) + 1
            for tag in entry.get_functional_categories():
                tag_dist[tag] = tag_dist.get(tag, 0) + 1

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
        for tag, count in sorted(tag_dist.items(), key=lambda item: item[1], reverse=True)[:15]:
            lines.append(f"  {tag}: {count}")

        return "\n".join(lines) + self._index_state_warning(idx)

    def get_indexed_function_detail(self, function_name: str) -> str:
        idx, gate_msg = self._ensure_index_ready(ToolNames.GET_INDEXED_FUNCTION_DETAIL)
        if gate_msg:
            return gate_msg

        warning = self._index_state_warning(idx)
        entry = idx.get_entry_by_name(function_name)
        if entry is None:
            entry = idx.get_entry_by_address(function_name)
        if entry is None:
            return f"Function '{function_name}' not found in the index.{warning}"

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
        return "\n".join(lines) + warning

    def ask_index_agent(self, query: str) -> str:
        idx, gate_msg = self._ensure_index_ready(ToolNames.ASK_INDEX_AGENT)
        if gate_msg:
            return gate_msg

        warning = ""
        if (getattr(idx, "indexing_state", "") or "").upper() != "COMPLETED":
            warning = (
                "**Warning:** The function index is not fully complete. "
                "The IndexAgent's analysis may be based on partial data, potentially affecting the quality of its recommendations. "
                "For best results, please ensure the binary is fully indexed.\n\n"
            )

        from ..backend.index_agent import IndexAgent

        start_ts = time.perf_counter()
        agent = IndexAgent()
        result = agent.search_index(query)
        elapsed_ms = (time.perf_counter() - start_ts) * 1000.0
        print(f"[AETHER Chatbot] IndexAgent returned a briefing packet in {elapsed_ms:.2f} ms using model={agent.model}")
        return warning + result


CHATBOT_TOOL_REGISTRY = {tool_name: getattr(ChatbotToolbox, tool_name.value) for tool_name in ToolNames}
TOOL_REGISTRY = CHATBOT_TOOL_REGISTRY
