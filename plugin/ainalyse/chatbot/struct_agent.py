from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable

from .agent_messaging import StructRequestPayload, StructResponsePayload, StructTaskStatus
from .chatbot_ida.bridge import ChatbotBackendBridge, IDAChatbotBackendBridge
from .chatbot_ida.struct_toolset import StructToolNames, StructToolbox
from .logging_utils import get_chatbot_logger
from .multi_agent_runtime import CallbackAgent, ContextBudget, ContextManager, MultiAgentRuntime
from .multi_agent_runtime.runtime.agent import AgentLoopExecutor, AgentLoopState
from .multi_agent_runtime.services.memory import MemoryPriority
from .multi_agent_runtime.services.planning import ActionStatus


STRUCT_AGENT_ID = "struct_agent"
STRUCT_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "struct_agent.txt")
STRUCT_EXTRA_TOOLS = {
    "add_action_plan",
    "add_task_to_plan",
    "update_task",
    "remove_action_plan",
    "add_memory",
    "remove_memory",
    "search_memory",
}


@dataclass(slots=True)
class StructAgentState:
    last_request_id: str = ""
    pending_questions: list[str] = field(default_factory=list)
    last_status: StructTaskStatus | None = None


class StructAgent:
    MAX_MUTATIONS_PER_REQUEST = 20
    LOOP_AGENT_ID = "struct_agent_loop"

    def __init__(self, bridge: ChatbotBackendBridge | None = None):
        self.bridge = bridge or IDAChatbotBackendBridge()
        self.toolbox = StructToolbox(self.bridge)
        self.state = StructAgentState()
        self.system_prompt = self._load_prompt()
        self.logger = get_chatbot_logger("chatbot.struct_agent")
        self.allowed_tools = {
            "struct_create",
            "struct_get_definition",
            "struct_list",
            "struct_resolve_offset_expr",
            "struct_get_next_offset",
            "struct_add_field",
            "struct_update_field",
            "struct_remove_field",
            "struct_apply_to_variable_or_address",
            "struct_rename",
            "struct_set_size",
            "struct_request_more_context",
            "get_function_pseudocode",
            "get_data_at_address",
            "get_xrefs_to",
            *STRUCT_EXTRA_TOOLS,
        }
        self._last_transcript: list[str] = []
        self.runtime = MultiAgentRuntime()
        if self.LOOP_AGENT_ID not in self.runtime.agents:
            self.runtime.add_agent(
                CallbackAgent(self.LOOP_AGENT_ID, lambda agent, message, ctx: None, description="StructAgent loop")
            )
        self.context_manager = ContextManager(
            budget=ContextBudget(),
            memory_store=self.runtime.get_agent_memory_store(self.LOOP_AGENT_ID),
        )
        self.context_manager.set_plan_manager(self.runtime.get_agent_plan_manager(self.LOOP_AGENT_ID))

    def _append_transcript(self, line: str) -> None:
        self._last_transcript.append(str(line))

    def get_transcript_snapshot(self) -> list[str]:
        return list(self._last_transcript)

    def consume_last_transcript(self) -> list[str]:
        transcript = list(self._last_transcript)
        self._last_transcript.clear()
        return transcript

    @staticmethod
    def _truncate_log_text(value: Any, max_len: int = 100) -> str:
        text = str(value)
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _load_prompt(self) -> str:
        try:
            with open(STRUCT_PROMPT_PATH, "r", encoding="utf-8") as handle:
                f_string_code = 'f"""' + handle.read() + '"""'
                safe_globals = {
                    "ToolNames": StructToolNames,
                    "StructToolNames": StructToolNames,
                    "StructTaskStatus": StructTaskStatus,
                }
                return eval(f_string_code, safe_globals, {}).strip()
        except Exception:
            return (
                "You are the StructAgent. Produce safe, minimal struct-oriented guidance. "
                "If context is insufficient, ask concise follow-up questions."
            )

    def get_tool_definitions(self) -> list[dict[str, object]]:
        definitions = list(self.toolbox.get_tool_definitions())
        definitions.extend(
            [
                {
                    "type": "function",
                    "function": {
                        "name": "add_action_plan",
                        "description": "Create and insert a new action plan.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "plan_index": {"type": "string"},
                                "description": {"type": "string"},
                            },
                            "required": ["plan_index", "description"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "add_task_to_plan",
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
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "update_task",
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
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "remove_action_plan",
                        "description": "Remove a completed or abandoned action plan.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "plan_index": {"type": "string"},
                            },
                            "required": ["plan_index"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "add_memory",
                        "description": "Store a memory item.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "key": {"type": "string"},
                                "value": {"type": "string"},
                                "category": {"type": "string"},
                                "priority": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                                "tags": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["key", "value", "category"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "remove_memory",
                        "description": "Remove a memory item by memory_id, key, or index.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "memory_id": {"type": "string"},
                                "key": {"type": "string"},
                                "index": {"type": "string"},
                            },
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "search_memory",
                        "description": "Search stored memories relevant to a query.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string"},
                                "top_k": {"type": "string"},
                            },
                            "required": ["query"],
                        },
                    },
                },
            ]
        )
        return definitions

    def execute_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> str:
        if tool_name not in self.allowed_tools:
            return f"[SYSTEM_ERROR] Tool '{tool_name}' is BLOCKED for StructAgent."
        arguments = arguments or {}
        if tool_name in STRUCT_EXTRA_TOOLS:
            return self._execute_runtime_tool(tool_name, arguments)
        return self.toolbox.execute_named(tool_name, arguments or {})

    def _execute_runtime_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        plan_manager = self.runtime.get_agent_plan_manager(self.LOOP_AGENT_ID)
        memory_store = self.runtime.get_agent_memory_store(self.LOOP_AGENT_ID)

        if tool_name == "add_action_plan":
            plan_index = int(str(arguments.get("plan_index", "0") or "0"))
            description = str(arguments.get("description", "") or "").strip()
            if not description:
                return "Error: description is required."
            plan_manager.create_plan(goal=description, actions=[], set_active=True, index=plan_index)
            return f"Action plan {plan_index} added: {description}"

        if tool_name == "add_task_to_plan":
            plan_index = int(str(arguments.get("plan_index", "0") or "0"))
            task_index = int(str(arguments.get("task_index", "-1") or "-1"))
            description = str(arguments.get("description", "") or "").strip()
            plans = plan_manager.all_plans
            if not (0 <= plan_index < len(plans)):
                return f"Error: ActionPlan with index {plan_index} not found."
            if not description:
                return "Error: description is required."
            index = None if task_index < 0 else task_index
            plans[plan_index].add_action(description=description, index=index)
            rendered_task_index = len(plans[plan_index].actions) - 1 if index is None else index
            return f"Task {rendered_task_index} added to plan {plan_index}: {description}"

        if tool_name == "update_task":
            plan_index = int(str(arguments.get("plan_index", "0") or "0"))
            task_index = int(str(arguments.get("task_index", "0") or "0"))
            status = str(arguments.get("status", "") or "").strip()
            plans = plan_manager.all_plans
            if not (0 <= plan_index < len(plans)):
                return f"Error: ActionPlan with index {plan_index} not found."
            actions = plans[plan_index].actions
            if not (0 <= task_index < len(actions)):
                return f"Error: Task with index {task_index} not found in plan {plan_index}."
            mapping = {
                StructTaskStatus.NOT_STARTED.value: ActionStatus.PENDING,
                StructTaskStatus.IN_PROGRESS.value: ActionStatus.IN_PROGRESS,
                StructTaskStatus.COMPLETED.value: ActionStatus.COMPLETED,
                StructTaskStatus.FAILED.value: ActionStatus.FAILED,
                "Not Started": ActionStatus.PENDING,
                "In Progress": ActionStatus.IN_PROGRESS,
                "Completed": ActionStatus.COMPLETED,
                "Failed": ActionStatus.FAILED,
            }
            if status not in mapping:
                return f"Error: Invalid status '{status}'."
            actions[task_index].status = mapping[status]
            return f"Task {task_index} in plan {plan_index} updated to {status}"

        if tool_name == "remove_action_plan":
            plan_index = int(str(arguments.get("plan_index", "0") or "0"))
            plans = plan_manager.all_plans
            if not (0 <= plan_index < len(plans)):
                return f"Error: ActionPlan with index {plan_index} not found."
            plan_id = plans[plan_index].id
            plan_manager.remove_plan(plan_id)
            return f"Action plan {plan_index} removed."

        if tool_name == "add_memory":
            key = str(arguments.get("key", "") or "").strip()
            value = arguments.get("value", "")
            category = str(arguments.get("category", "general") or "general")
            priority_str = str(arguments.get("priority", "MEDIUM") or "MEDIUM").upper()
            tags = arguments.get("tags")
            if not key:
                return "Error: key is required."
            try:
                priority = MemoryPriority[priority_str]
            except KeyError:
                priority = MemoryPriority.MEDIUM
            memory_store.add_memory(
                key=key,
                value=value,
                category=category,
                priority=priority,
                tags=list(tags or []),
                metadata={},
            )
            return f"Memory stored successfully (Key: {key}, Category: {category}, Priority: {priority.name})"

        if tool_name == "remove_memory":
            memory_id = str(arguments.get("memory_id", "") or "").strip() or None
            key = str(arguments.get("key", "") or "").strip() or None
            index_raw = str(arguments.get("index", "") or "").strip()
            index = int(index_raw) if index_raw else None
            memory_items = list(memory_store.memories.values())
            target_id = memory_id
            if target_id is not None and target_id not in memory_store.memories:
                return f"Error: Memory with id '{target_id}' not found."
            if target_id is None and index is not None:
                if not (0 <= index < len(memory_items)):
                    return f"Error: Memory with index {index} not found."
                target_id = memory_items[index].id
            if target_id is None and key is not None:
                for memory in memory_items:
                    if memory.key == key:
                        target_id = memory.id
                        break
            if not target_id:
                return "Error: Must provide a valid memory_id, key, or index."
            memory_store.delete_memory(target_id)
            return "Memory removed successfully."

        if tool_name == "search_memory":
            query = str(arguments.get("query", "") or "").strip()
            top_k_raw = str(arguments.get("top_k", "5") or "5")
            if not query:
                return "Error: query is required."
            try:
                top_k = max(1, int(top_k_raw))
            except ValueError:
                top_k = 5
            results = memory_store.search_memories(query=query, top_k=top_k)
            if not results:
                return f"No memory results found for query '{query}'."
            lines = [f"Found {len(results)} memory result(s) for '{query}':"]
            for item in results:
                memory = item.memory
                lines.append(f"- [{memory.id}] key={memory.key or '<none>'} category={memory.category} value={memory.value}")
            return "\n".join(lines)

        return f"Error: Unsupported runtime tool '{tool_name}'."

    def _estimate_mutation_count(self, metadata: dict[str, Any]) -> int:
        proposed_edits = metadata.get("proposed_edits")
        if isinstance(proposed_edits, list):
            return len(proposed_edits)
        return 0

    def _ask_llm_for_struct_guidance(self, request: StructRequestPayload) -> dict[str, Any] | None:
        try:
            from ainalyse import load_config
            from ainalyse.ssl_helper import create_openai_client_with_custom_ca

            config = load_config()
            api_key = config.get("OPENAI_API_KEY")
            if not api_key:
                return None

            client = create_openai_client_with_custom_ca(
                api_key,
                config.get("OPENAI_BASE_URL"),
                config.get("CUSTOM_CA_CERT_PATH", ""),
                config.get("CLIENT_CERT_PATH", ""),
                config.get("CLIENT_KEY_PATH", ""),
                "struct_agent",
            )
            messages = [
                {"role": "system", "content": self.system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "request_id": request.request_id,
                            "suggested_struct_name": request.suggested_struct_name,
                            "relevant_functions": request.relevant_functions,
                            "context_description": request.context_description,
                            "metadata": request.metadata,
                        },
                        ensure_ascii=False,
                    ),
                },
            ]
            response = client.chat.completions.create(
                model=config.get("OPENAI_MODEL", "gpt-4o-mini"),
                messages=messages,
                max_tokens=600,
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            content = getattr(response.choices[0].message, "content", "") if response and response.choices else ""
            if not content:
                return None
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
        return None

    @staticmethod
    def _normalize_tool_calls(message: Any) -> list[dict[str, Any]]:
        normalized = []
        for tool_call in getattr(message, "tool_calls", []) or []:
            raw_arguments = getattr(getattr(tool_call, "function", None), "arguments", "{}")
            try:
                arguments = json.loads(raw_arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
            normalized.append(
                {
                    "id": getattr(tool_call, "id", ""),
                    "name": getattr(getattr(tool_call, "function", None), "name", ""),
                    "arguments": arguments,
                    "raw_arguments": raw_arguments,
                }
            )
        return normalized

    @staticmethod
    def _is_valid_tool_call(tool_call: dict[str, Any]) -> bool:
        return bool(str(tool_call.get("id", "")).strip()) and bool(str(tool_call.get("name", "")).strip())

    def create_text_session(
        self,
        text: str,
        request_id: str = "",
        relevant_functions: list[str] | None = None,
        context_description: str = "",
    ) -> dict[str, Any]:
        from ainalyse import load_config
        from ainalyse.ssl_helper import create_openai_client_with_custom_ca

        self._last_transcript = []

        prompt_text = (text or "").strip()
        request_line = f"request: {self._truncate_log_text(prompt_text, 240)}"
        self._append_transcript(request_line)
        self.logger.info(
            "StructAgent request start request_id=%s msg_len=%s relevant_functions=%s",
            request_id,
            len(prompt_text),
            list(relevant_functions or []),
        )

        config = load_config()
        api_key = config.get("OPENAI_API_KEY")
        retry_count = max(0, int(config.get("CHATBOT_REQUEST_RETRIES", 2)))
        retry_base_delay_sec = max(0.0, float(config.get("CHATBOT_REQUEST_RETRY_DELAY_SEC", 1.0)))
        if not api_key:
            return {
                "done": True,
                "response_text": "StructAgent cannot process request: OPENAI_API_KEY is not configured.",
                "error": True,
            }

        client = create_openai_client_with_custom_ca(
            api_key,
            config.get("OPENAI_BASE_URL"),
            config.get("CUSTOM_CA_CERT_PATH", ""),
            config.get("CLIENT_CERT_PATH", ""),
            config.get("CLIENT_KEY_PATH", ""),
            "struct_agent",
        )
        request_payload = json.dumps(
            {
                "request_id": request_id,
                "message": prompt_text,
                "relevant_functions": list(relevant_functions or []),
                "context_description": context_description,
            },
            ensure_ascii=False,
        )
        conversation_history: list[dict[str, Any]] = [{"role": "user", "content": request_payload}]
        tool_handlers = {
            tool_name.value: (lambda _tool_name: (lambda **arguments: self.execute_tool(_tool_name, arguments)))(tool_name.value)
            for tool_name in StructToolNames
        }
        executor = AgentLoopExecutor(
            client=client,
            model=config.get("OPENAI_MODEL", "gpt-4o-mini"),
            max_iterations=-1,
            system_prompt=self.system_prompt,
            tools=self.get_tool_definitions(),
            tool_handlers=tool_handlers,
            context_manager=self.context_manager,
            plan_manager=self.runtime.get_agent_plan_manager(self.LOOP_AGENT_ID),
            memory_store=self.runtime.get_agent_memory_store(self.LOOP_AGENT_ID),
            copy_reasoning_to_content=False,
            llm_retry_count=retry_count,
            llm_retry_base_delay_sec=retry_base_delay_sec,
        )
        state = executor.create_state(
            task=prompt_text,
            conversation_history=conversation_history,
        )
        return {
            "executor": executor,
            "state": state,
            "request_id": request_id,
            "done": False,
            "response_text": "",
        }

    def step_text_session(self, session: dict[str, Any]) -> dict[str, Any]:
        if bool(session.get("done", False)):
            return session
        request_id = str(session.get("request_id", ""))
        try:
            executor = session["executor"]
            state = session["state"]
            if not isinstance(state, AgentLoopState):
                session["done"] = True
                session["response_text"] = "StructAgent session state is invalid."
                return session
            step = executor.step(state)
            assistant_message = step.assistant_message or {}
            interim_text = str(assistant_message.get("content", "") or "").strip()
            if interim_text:
                self._append_transcript(f"assistant: {self._truncate_log_text(interim_text, 300)}")
            for tool_result in list(step.tool_results or []):
                self._append_transcript(
                    f"tool: {tool_result.get('name', '')} args={self._truncate_log_text(tool_result.get('arguments', {}), 140)} result={self._truncate_log_text(tool_result.get('result', ''), 200)}"
                )
            if not step.done:
                return session
            content = str(step.final_analysis or "").strip()
            session["done"] = True
            if content:
                session["response_text"] = content
                self._append_transcript(f"reply: {self._truncate_log_text(content, 300)}")
            else:
                session["response_text"] = "StructAgent responded without textual content."
                self._append_transcript("reply: <empty>")
            return session
        except Exception as exc:
            self.logger.exception("StructAgent failed to process request_id=%s: %s", request_id, exc)
            self._append_transcript(f"error: {exc}")
            session["done"] = True
            session["response_text"] = f"StructAgent failed to process request: {exc}"
            return session

    def handle_text_request(
        self,
        text: str,
        request_id: str = "",
        relevant_functions: list[str] | None = None,
        context_description: str = "",
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> str:
        def _emit_progress(*, line: str = "", response_text: str = "") -> None:
            if progress_callback is None:
                return
            payload = {
                "line": str(line or ""),
                "response_text": str(response_text or ""),
                "request_id": str(request_id or ""),
            }
            try:
                progress_callback(payload)
            except Exception:
                self.logger.debug("StructAgent progress callback failed", exc_info=True)

        self._last_transcript = []
        prompt_text = (text or "").strip()
        if not prompt_text:
            return "StructAgent received an empty request."
        request_line = f"request: {self._truncate_log_text(prompt_text, 240)}"
        self._append_transcript(request_line)
        _emit_progress(line=request_line)
        self.logger.info(
            "StructAgent request start request_id=%s msg_len=%s relevant_functions=%s",
            request_id,
            len(prompt_text),
            list(relevant_functions or []),
        )

        try:
            session = self.create_text_session(
                prompt_text,
                request_id=request_id,
                relevant_functions=relevant_functions,
                context_description=context_description,
            )
            if bool(session.get("done", False)):
                return str(session.get("response_text", "") or "StructAgent returned an empty response.")

            cursor = 0
            while not bool(session.get("done", False)):
                session = self.step_text_session(session)
                snapshot = self.get_transcript_snapshot()
                if cursor < len(snapshot):
                    for line in snapshot[cursor:]:
                        if str(line or "").strip():
                            _emit_progress(line=str(line))
                    cursor = len(snapshot)

            response_text = str(session.get("response_text", "") or "StructAgent returned an empty response.")
            if response_text and not response_text.startswith("StructAgent failed to process request:"):
                _emit_progress(response_text=response_text)
            return response_text
        except Exception as exc:
            self.logger.exception("StructAgent failed to process request_id=%s: %s", request_id, exc)
            error_line = f"error: {exc}"
            self._append_transcript(error_line)
            _emit_progress(line=error_line)
            return f"StructAgent failed to process request: {exc}"

    def handle_struct_request(self, payload: dict[str, Any]) -> StructResponsePayload:
        request = StructRequestPayload.from_dict(payload)
        self.state.last_request_id = request.request_id
        dry_run = bool((request.metadata or {}).get("dry_run", False))
        estimated_mutations = self._estimate_mutation_count(request.metadata)
        llm_guidance = self._ask_llm_for_struct_guidance(request)

        if not request.suggested_struct_name.strip():
            self.state.last_status = StructTaskStatus.FAILED
            return StructResponsePayload(
                status=StructTaskStatus.FAILED,
                details="Missing suggested_struct_name.",
                requests_for_main_agent=["Provide a suggested struct name."],
                request_id=request.request_id,
            )

        if not request.relevant_functions:
            self.state.last_status = StructTaskStatus.FAILED
            return StructResponsePayload(
                status=StructTaskStatus.FAILED,
                details="No relevant functions were provided.",
                requests_for_main_agent=["Provide at least one relevant function name."],
                request_id=request.request_id,
            )

        if estimated_mutations > self.MAX_MUTATIONS_PER_REQUEST:
            self.state.last_status = StructTaskStatus.FAILED
            return StructResponsePayload(
                status=StructTaskStatus.FAILED,
                details=(
                    f"Request exceeds mutation limit: {estimated_mutations} > "
                    f"{self.MAX_MUTATIONS_PER_REQUEST}."
                ),
                requests_for_main_agent=["Reduce struct edits in a single request."],
                request_id=request.request_id,
                metadata={"error_code": "MUTATION_LIMIT_EXCEEDED"},
            )

        if dry_run:
            self.state.last_status = StructTaskStatus.MODIFIED
            return StructResponsePayload(
                status=StructTaskStatus.MODIFIED,
                details=(
                    "Dry-run accepted. Struct agent will not mutate IDA types in this mode. "
                    "Provide confirmation with dry_run=false to apply changes."
                ),
                requests_for_main_agent=[],
                request_id=request.request_id,
                warnings=["No changes were applied (dry_run=true)."],
                metadata={
                    "dry_run": True,
                    "suggested_struct_name": request.suggested_struct_name,
                },
            )

        if llm_guidance and bool(llm_guidance.get("needs_more_context", False)):
            questions = llm_guidance.get("requests_for_main_agent") or llm_guidance.get("questions") or []
            question_list = [str(question) for question in questions if str(question).strip()]
            if question_list:
                self.state.last_status = StructTaskStatus.FAILED
                return StructResponsePayload(
                    status=StructTaskStatus.FAILED,
                    details="StructAgent needs more context before applying type changes.",
                    requests_for_main_agent=question_list,
                    request_id=request.request_id,
                    metadata={"error_code": "INSUFFICIENT_CONTEXT"},
                )

        creation = self.toolbox.struct_create(request.suggested_struct_name)
        lowered = creation.lower()
        if "error" in lowered or "failed" in lowered:
            self.state.last_status = StructTaskStatus.FAILED
            return StructResponsePayload(
                status=StructTaskStatus.FAILED,
                details=creation,
                requests_for_main_agent=["Provide more concrete field hypotheses (name, type, offset expression)."],
                request_id=request.request_id,
                metadata={"error_code": "STRUCT_CREATE_FAILED"},
            )

        status = StructTaskStatus.MODIFIED if "already exists" in lowered else StructTaskStatus.CREATED
        self.state.last_status = status
        return StructResponsePayload(
            status=status,
            details=creation,
            requests_for_main_agent=[],
            request_id=request.request_id,
            metadata={
                "suggested_struct_name": request.suggested_struct_name,
                "relevant_functions": request.relevant_functions,
                "context_description": request.context_description,
            },
        )


__all__ = ["STRUCT_AGENT_ID", "StructAgent", "StructAgentState"]
