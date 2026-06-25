from __future__ import annotations

import json
import time
from enum import StrEnum
from typing import Any

from .chatbot_ida.bridge import ChatbotBackendBridge, IDAChatbotBackendBridge
from .chatbot_ida.toolset import ChatbotToolbox, ToolNames
from .logging_utils import get_chatbot_logger
from .multi_agent_runtime import CallbackAgent, MultiAgentRuntime
from .multi_agent_runtime.runtime.agent import AgentLoopExecutor, AgentLoopState, AgentLoopStep
from .multi_agent_runtime.runtime.context import ContextBudget, ContextManager
from .multi_agent_runtime.runtime.context.summarizer_agent import SummarizerAgent
from .multi_agent_runtime.services.memory import (
    HierarchicalRetrievalAgent,
    KeywordRetrievalAgent,
    MemoryPriority,
    OpenAILLMClient,
)
from .multi_agent_runtime.services.planning import Action, ActionStatus, Plan
from .specialist_orchestrator import SpecialistOrchestrator


MAX_FUNCTION_LIST_SIZE = 10
CHATBOT_RUNTIME_AGENT_ID = "chatbot"


class TaskStatus(StrEnum):
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    FAILED = "Failed"


class ChatbotAgentState:
    def __init__(
        self,
        *,
        bridge: ChatbotBackendBridge | None = None,
        runtime: MultiAgentRuntime | None = None,
        agent_id: str = CHATBOT_RUNTIME_AGENT_ID,
    ):
        self.bridge = bridge or IDAChatbotBackendBridge()
        self.logger = get_chatbot_logger("chatbot.agent")
        self.runtime = runtime or MultiAgentRuntime()
        self.agent_id = agent_id
        if agent_id not in self.runtime.agents:
            self.runtime.add_agent(CallbackAgent(agent_id, lambda agent, message, ctx: None, description="AETHER chatbot"))
        context = self.runtime.get_agent_context(agent_id)
        context.setdefault("function_list", [])
        self._configure_memory_retrieval()
        self.context_manager = ContextManager(
            budget=ContextBudget(),
            memory_store=self.memory_store,
        )
        self.context_manager.set_plan_manager(self.plan_manager)
        self.context_manager.set_agent_state_provider(self.render_memory_statistics)
        self.specialist_orchestrator = None

    def delegate_struct_task(
        self,
        *,
        message: str,
        relevant_functions: list[str],
        context_description: str = "",
    ) -> str:
        if self.specialist_orchestrator is None:
            raise RuntimeError("Specialist orchestrator is not configured.")
        return self.specialist_orchestrator.send_struct_message(
            message=message,
            relevant_functions=relevant_functions,
            context_description=context_description,
        )

    @property
    def context(self) -> dict[str, Any]:
        return self.runtime.get_agent_context(self.agent_id)

    @property
    def memory_store(self):
        return self.runtime.get_agent_memory_store(self.agent_id)

    @property
    def plan_manager(self):
        return self.runtime.get_agent_plan_manager(self.agent_id)

    def _configure_memory_retrieval(self) -> None:
        try:
            from ainalyse import load_config

            config = load_config()
            api_key = config.get("OPENAI_API_KEY")
            if not api_key:
                self.memory_store.set_retrieval_agent(KeywordRetrievalAgent(self.memory_store))
                return
            llm_client = OpenAILLMClient(
                api_key=api_key,
                model=config.get("OPENAI_MEMORY_MODEL") or config.get("OPENAI_MODEL", "gpt-4o-mini"),
                base_url=config.get("OPENAI_BASE_URL") or None,
            )
            self.memory_store.set_retrieval_agent(HierarchicalRetrievalAgent(self.memory_store, llm_client))
        except Exception as exc:
            self.logger.warning("Falling back to keyword memory retrieval: %s", exc)
            self.memory_store.set_retrieval_agent(KeywordRetrievalAgent(self.memory_store))

    @property
    def function_list(self) -> list[Any]:
        return self.context.setdefault("function_list", [])

    @function_list.setter
    def function_list(self, value: list[Any]) -> None:
        self.context["function_list"] = value

    @property
    def conversation_history(self) -> list[dict[str, str]]:
        return self.runtime.get_agent_conversation_history(self.agent_id)

    @conversation_history.setter
    def conversation_history(self, value: list[dict[str, str]]) -> None:
        self.runtime.set_agent_conversation_history(self.agent_id, value)

    def _get_plan(self, plan_index: int) -> Plan | None:
        plans = self.plan_manager.all_plans
        if 0 <= plan_index < len(plans):
            return plans[plan_index]
        return None

    def _get_task(self, plan_index: int, task_index: int) -> Action | None:
        plan = self._get_plan(plan_index)
        if plan and 0 <= task_index < len(plan.actions):
            return plan.actions[task_index]
        return None

    def add_memory(
        self,
        key: str,
        value: Any,
        category: str = "chatbot_short_term",
        priority: str | MemoryPriority = MemoryPriority.MEDIUM,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if isinstance(priority, str):
            try:
                priority = MemoryPriority[priority.upper()]
            except KeyError:
                priority = MemoryPriority.MEDIUM

        for memory_id, memory in self.memory_store.memories.items():
            if memory.key == key:
                self.memory_store.update_memory(
                    memory_id,
                    value=value,
                    key=key,
                    tags=list(tags or memory.tags),
                    metadata=metadata,
                )
                memory.category = category
                memory.priority = priority
                return
        self.memory_store.add_memory(
            key=key,
            value=value,
            category=category,
            priority=priority,
            tags=list(tags or ["short_term"]),
            metadata=dict(metadata or {}),
        )

    def remove_memory(
        self,
        key: str | None = None,
        index: int | None = None,
        memory_id: str | None = None,
    ) -> None:
        if key is None and index is None and memory_id is None:
            raise ValueError("Must provide a memory_id, key, or index to remove memory.")
        memory_items = list(self.memory_store.memories.values())
        memory_id_to_remove = memory_id
        if memory_id_to_remove is not None and memory_id_to_remove not in self.memory_store.memories:
            raise KeyError(f"Memory with id '{memory_id_to_remove}' not found.")
        elif index is not None:
            if not 0 <= index < len(memory_items):
                raise IndexError(f"Memory with index {index} not found.")
            memory_id_to_remove = memory_items[index].id
        elif key is not None:
            for memory in memory_items:
                if memory.key == key:
                    memory_id_to_remove = memory.id
                    break
        if not memory_id_to_remove:
            raise KeyError(f"Memory with key '{key}' not found.")
        self.memory_store.delete_memory(memory_id_to_remove)

    def add_action_plan(self, description: str, task_descriptions: list[str], index: int | None = None) -> None:
        self.plan_manager.create_plan(
            goal=description,
            actions=[{"description": task_description} for task_description in task_descriptions],
            set_active=True,
            index=index,
        )

    def add_task_to_plan(self, plan_index: int, description: str, index: int | None = None) -> None:
        plan = self._get_plan(plan_index)
        if plan is None:
            raise IndexError(f"ActionPlan with index {plan_index} not found.")
        plan.add_action(description=description, index=index)

    def update_task(self, plan_index: int, task_index: int, status: TaskStatus) -> None:
        task = self._get_task(plan_index, task_index)
        if task is None:
            raise IndexError(f"Task with index {task_index} not found in plan {plan_index}.")
        task.status = _to_action_status(status)

    def remove_task_from_plan(self, plan_index: int, task_index: int) -> None:
        plan = self._get_plan(plan_index)
        if plan is None or not 0 <= task_index < len(plan.actions):
            raise IndexError(f"Task with index {task_index} not found in plan {plan_index}.")
        del plan.actions[task_index]

    def remove_action_plan(self, plan_index: int) -> None:
        plan = self._get_plan(plan_index)
        if plan is None:
            raise IndexError(f"ActionPlan with index {plan_index} not found.")
        self.plan_manager.remove_plan(plan.id)

    def add_to_function_list(self, function_name: str) -> str:
        function_ref = self.bridge.resolve_function(function_name)
        if function_ref is None:
            return f"Error: Function '{function_name}' not found."
        if function_ref in self.function_list:
            return f"'{function_name}' is already in the analysis list."
        if len(self.function_list) >= MAX_FUNCTION_LIST_SIZE:
            return f"Function List is full (max {MAX_FUNCTION_LIST_SIZE})"
        self.function_list.append(function_ref)
        return f"Added '{function_name}' to analysis list."

    def remove_from_function_list(self, function_name: str) -> None:
        function_ref = self.bridge.resolve_function(function_name)
        if function_ref is None:
            raise KeyError(f"Function '{function_name}' not found.")
        try:
            self.function_list.remove(function_ref)
        except ValueError as exc:
            raise KeyError(f"Function '{function_name}' not found in analysis list.") from exc

    def clear_all_plans(self) -> None:
        self.plan_manager.clear()

    def clear_memory(self) -> None:
        self.memory_store.clear()
        self.runtime.clear_agent_plan(self.agent_id)
        self.runtime.clear_agent_context(self.agent_id)
        self.runtime.clear_agent_conversation_history(self.agent_id)
        self.context_manager = ContextManager(
            budget=ContextBudget(),
            memory_store=self.memory_store,
        )
        self.context_manager.set_plan_manager(self.plan_manager)
        self.context_manager.set_agent_state_provider(self.render_memory_statistics)
        self.context.update(
            {
                "function_list": [],
            }
        )

    def render_memory_statistics(self) -> str:
        stats = self.memory_store.get_statistics()
        memories = list(self.memory_store.memories.values())
        memory_tags = sorted({tag for memory in memories for tag in memory.tags})
        memory_categories = stats.get("categories", {})
        memory_priority_counts = stats.get("priorities", {})
        return "\n".join(
            [
                "[MEMORY STATISTICS]",
                f"Total Memories: {len(memories)}",
                f"Tags: [{', '.join(memory_tags) if memory_tags else 'none'}]",
                f"Categories: {_format_counts(memory_categories)}",
                f"Priorities: {_format_counts(memory_priority_counts)}",
            ]
        )

    def __str__(self) -> str:
        memories = list(self.memory_store.memories.values())
        memory_tags = sorted({tag for memory in memories for tag in memory.tags})
        memory_categories = self.memory_store.get_statistics().get("categories", {})
        memory_priority_counts = self.memory_store.get_statistics().get("priorities", {})
        memory_str = "\n".join(
            [
                f"  - Total Memories: {len(memories)}",
                f"  - Tags: [{', '.join(memory_tags) if memory_tags else 'none'}]",
                f"  - Categories: {_format_counts(memory_categories)}",
                f"  - Priorities: {_format_counts(memory_priority_counts)}",
            ]
        )

        plans = self.plan_manager.all_plans
        if plans:
            plan_str = "\n".join(f"--- Plan {index} ---\n{_format_plan(plan)}" for index, plan in enumerate(plans))
        else:
            plan_str = "No active plans."

        function_names = [self.bridge.get_function_name(function_ref) for function_ref in self.function_list]
        return (
            "ChatbotAgentState:\n"
            f"- Memory Store:\n{memory_str}\n"
            f"- Plan Manager:\n{plan_str}\n"
            f"- Function List: [{', '.join(function_names)}]"
        )


def _to_action_status(status: TaskStatus) -> ActionStatus:
    return {
        TaskStatus.NOT_STARTED: ActionStatus.PENDING,
        TaskStatus.IN_PROGRESS: ActionStatus.IN_PROGRESS,
        TaskStatus.COMPLETED: ActionStatus.COMPLETED,
        TaskStatus.FAILED: ActionStatus.FAILED,
    }[status]


def _from_action_status(status: ActionStatus) -> TaskStatus:
    return {
        ActionStatus.PENDING: TaskStatus.NOT_STARTED,
        ActionStatus.IN_PROGRESS: TaskStatus.IN_PROGRESS,
        ActionStatus.COMPLETED: TaskStatus.COMPLETED,
        ActionStatus.FAILED: TaskStatus.FAILED,
        ActionStatus.SKIPPED: TaskStatus.COMPLETED,
    }[status]


def _format_plan(plan: Plan) -> str:
    if not plan.actions:
        return plan.goal
    task_lines = [
        f"  '{_from_action_status(action.status).value}' {action.description} (ID: {index})"
        for index, action in enumerate(plan.actions)
    ]
    return f"{plan.goal}\n" + "\n".join(task_lines)


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


class ChatbotContextSummarizer:
    def __init__(self, *, summarizer_agent: SummarizerAgent | None = None, toolbox: ChatbotToolbox | None = None):
        self.summarizer_agent = summarizer_agent
        self.toolbox = toolbox

    async def summarize(self, state: ChatbotAgentState, finalize: bool = False) -> str:
        if len(state.conversation_history) < 2:
            return "Not enough history to summarize."

        manager = state.context_manager
        manager.block_buffer.clear()
        for message in state.conversation_history:
            manager.block_buffer.add_message(message)

        blocks = list(manager.block_buffer.blocks)
        blocks_to_summarize = blocks[:-2] if len(blocks) > 2 else blocks
        if self.summarizer_agent is not None:
            batch_summary = self.summarizer_agent.summarize_blocks(
                blocks_to_summarize,
                plan=state.plan_manager.active_plan,
            )
            summary_text = batch_summary.chronological_summary
        else:
            summary_text = "\n".join(
                manager.block_buffer._generate_summary(block)
                for block in blocks_to_summarize
            )
        if not summary_text:
            summary_text = "\n".join(
                f"{message.get('role', 'unknown')}: {message.get('content', '')}"
                for message in state.conversation_history
            )
        manager.block_buffer.add_to_variable_summary(
            summary_text,
            summarizer_agent=self.summarizer_agent,
        )

        final_text = manager.block_buffer.get_combined_summary()
        if self.toolbox is not None:
            self.toolbox.save_summary(final_text)
        return final_text if finalize else final_text


def _create_summarizer_agent(memory_store: Any | None = None) -> SummarizerAgent:
    from ainalyse import load_config

    config = load_config()
    return SummarizerAgent(
        api_key=config["OPENAI_API_KEY"],
        memory_store=memory_store,
        model=config.get("OPENAI_MODEL", "gpt-4"),
        base_url=config.get("OPENAI_BASE_URL") or None,
    )


def _normalize_tool_call(tool_call: Any) -> dict[str, Any]:
    raw_arguments = getattr(getattr(tool_call, "function", None), "arguments", "{}")
    try:
        arguments = json.loads(raw_arguments or "{}")
    except json.JSONDecodeError:
        arguments = {}
    return {
        "id": getattr(tool_call, "id", ""),
        "name": getattr(getattr(tool_call, "function", None), "name", ""),
        "arguments": arguments,
    }


def _normalize_completion_payload(response: Any) -> dict[str, Any]:
    if isinstance(response, str):
        return {"content": response.strip(), "tool_calls": []}
    choices = getattr(response, "choices", None)
    if not choices:
        raise ValueError("LLM returned an empty response.")
    message = getattr(choices[0], "message", None)
    if message is None:
        raise ValueError("LLM response did not contain a message.")
    content = getattr(message, "content", None) or ""
    tool_calls = [_normalize_tool_call(tool_call) for tool_call in getattr(message, "tool_calls", []) or []]
    return {
        "content": str(content).strip(),
        "tool_calls": tool_calls,
    }


def _assistant_message_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": payload["content"]}
    if payload["tool_calls"]:
        message["tool_calls"] = [
            {
                "id": tool_call["id"],
                "type": "function",
                "function": {
                    "name": tool_call["name"],
                    "arguments": json.dumps(tool_call["arguments"]),
                },
            }
            for tool_call in payload["tool_calls"]
        ]
    return message


class _ChatbotCompletionDefaults:
    def __init__(
        self,
        completions: Any,
        defaults: dict[str, Any],
        *,
        retry_count: int = 2,
        retry_base_delay_sec: float = 1.0,
        logger: Any | None = None,
    ):
        self._completions = completions
        self._defaults = defaults
        self._retry_count = max(0, int(retry_count))
        self._retry_base_delay_sec = max(0.0, float(retry_base_delay_sec))
        self._logger = logger

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        status_code = getattr(exc, "status_code", None)
        response = getattr(exc, "response", None)
        if status_code is None and response is not None:
            status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int):
            return status_code in {408, 409, 429} or status_code >= 500

        error_text = str(exc).lower()
        retryable_markers = (
            "timeout",
            "timed out",
            "temporarily unavailable",
            "connection reset",
            "connection refused",
            "connection aborted",
            "rate limit",
            "too many requests",
            "service unavailable",
            "internal server error",
            "bad gateway",
            "gateway timeout",
        )
        non_retryable_markers = (
            "invalid api key",
            "authentication",
            "unauthorized",
            "forbidden",
            "invalid_request",
            "bad request",
            "does not exist",
            "context_length_exceeded",
        )
        if any(marker in error_text for marker in non_retryable_markers):
            return False
        return any(marker in error_text for marker in retryable_markers)

    def create(self, **kwargs: Any) -> Any:
        request = dict(kwargs)
        for key, value in self._defaults.items():
            if value is not None:
                request.setdefault(key, value)
        attempts = self._retry_count + 1
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                return self._completions.create(**request)
            except Exception as exc:
                last_error = exc
                if attempt >= attempts or not self._is_retryable_error(exc):
                    raise
                delay_seconds = self._retry_base_delay_sec * (2 ** (attempt - 1))
                if self._logger is not None:
                    self._logger.warning(
                        "LLM completion failed (attempt %s/%s): %s. Retrying in %.2fs",
                        attempt,
                        attempts,
                        exc,
                        delay_seconds,
                    )
                time.sleep(delay_seconds)
        if last_error is not None:
            raise last_error
        raise RuntimeError("LLM completion retry loop exited unexpectedly.")


class _ChatbotChatDefaults:
    def __init__(
        self,
        chat: Any,
        defaults: dict[str, Any],
        *,
        retry_count: int = 2,
        retry_base_delay_sec: float = 1.0,
        logger: Any | None = None,
    ):
        self.completions = _ChatbotCompletionDefaults(
            chat.completions,
            defaults,
            retry_count=retry_count,
            retry_base_delay_sec=retry_base_delay_sec,
            logger=logger,
        )


class _ChatbotClientDefaults:
    def __init__(
        self,
        client: Any,
        defaults: dict[str, Any],
        *,
        retry_count: int = 2,
        retry_base_delay_sec: float = 1.0,
        logger: Any | None = None,
    ):
        self.chat = _ChatbotChatDefaults(
            client.chat,
            defaults,
            retry_count=retry_count,
            retry_base_delay_sec=retry_base_delay_sec,
            logger=logger,
        )


class ChatbotAgent:
    def __init__(self, *, bridge: ChatbotBackendBridge | None = None):
        self.logger = get_chatbot_logger("chatbot.agent")
        self.state = ChatbotAgentState(bridge=bridge)
        self.toolbox = ChatbotToolbox(self.state)
        self.specialist_orchestrator = SpecialistOrchestrator(self.state)
        self.state.specialist_orchestrator = self.specialist_orchestrator
        self.tool_definitions = self.toolbox.get_tool_definitions()
        self.current_steps: list[AgentLoopStep] = []
        self.last_step: AgentLoopStep | None = None

    def _get_retry_settings(self) -> tuple[int, float]:
        from ainalyse import load_config

        config = load_config()
        retry_count = max(0, int(config.get("CHATBOT_REQUEST_RETRIES", 2)))
        retry_base_delay_sec = max(0.0, float(config.get("CHATBOT_REQUEST_RETRY_DELAY_SEC", 1.0)))
        return retry_count, retry_base_delay_sec

    def get_tool_definitions(self, enabled_tools: set[str] | None = None) -> list[dict[str, object]]:
        return self.toolbox.get_tool_definitions(enabled_tools)

    def _create_openai_client(self, feature: str = "chatbot") -> Any:
        from ainalyse import load_config
        from ainalyse.ssl_helper import create_openai_client_with_custom_ca

        config = load_config()
        return create_openai_client_with_custom_ca(
            config["OPENAI_API_KEY"],
            config["OPENAI_BASE_URL"],
            config.get("CUSTOM_CA_CERT_PATH", ""),
            config.get("CLIENT_CERT_PATH", ""),
            config.get("CLIENT_KEY_PATH", ""),
            feature,
        )

    def _build_tool_handlers(
        self,
        *,
        enabled_tools: set[str] | None = None,
        max_tool_calls: int | None = None,
        max_cumulative_tool_output: int | None = None,
    ) -> dict[str, Any]:
        enabled = set(enabled_tools) if enabled_tools is not None else {tool_name.value for tool_name in ToolNames}
        runtime_tools = {tool_name.value for tool_name in ToolNames}
        executed_count = 0
        cumulative_len = 0
        handlers: dict[str, Any] = {}

        def execute_tool(tool_name: str, arguments: dict[str, Any]) -> str:
            if tool_name in (
                ToolNames.DELEGATE_STRUCT_TASK.value,
                ToolNames.ANNOTATE_FUNCTION.value,
            ):
                try:
                    return self.toolbox.execute_named(tool_name, arguments)
                except Exception as exc:
                    return f"Error executing {tool_name}: {exc}"
            try:
                import ida_kernwin
                from ainalyse.qt_shim import QtWidgets
            except Exception:
                return self.toolbox.execute_named(tool_name, arguments)

            result: dict[str, str] = {}

            def run_tool() -> int:
                try:
                    result["output"] = self.toolbox.execute_named(tool_name, arguments)
                except Exception as exc:
                    result["output"] = f"Error executing {tool_name}: {exc}"
                return 1

            app = QtWidgets.QApplication.instance()
            if app is None or app.closingDown():
                return f"Error executing {tool_name}: IDA is shutting down."

            ida_kernwin.execute_sync(run_tool, ida_kernwin.MFF_WRITE)
            return result.get("output", "")

        def make_handler(tool_name: str):
            def handler(**arguments: Any) -> str:
                nonlocal executed_count, cumulative_len
                if tool_name not in runtime_tools:
                    return f"[SYSTEM_ERROR] Tool '{tool_name}' is BLOCKED. Reason: UNKNOWN_TOOL."
                if tool_name not in enabled:
                    return f"[SYSTEM_ERROR] Tool '{tool_name}' is BLOCKED. Reason: DISABLED_BY_USER_SETTINGS."
                if max_tool_calls is not None and executed_count >= max_tool_calls:
                    return f"[SYSTEM_ERROR] Tool '{tool_name}' is BLOCKED. Reason: COUNT_LIMIT ({executed_count}/{max_tool_calls}). Retry with fewer tool calls."
                if max_cumulative_tool_output is not None and cumulative_len >= max_cumulative_tool_output:
                    return f"[SYSTEM_ERROR] Tool '{tool_name}' is BLOCKED. Reason: LENGTH_LIMIT ({cumulative_len}/{max_cumulative_tool_output} chars). Retry with fewer tool calls."
                executed_count += 1
                output = execute_tool(tool_name, arguments)
                cumulative_len += len(output)
                return output

            return handler

        for name in runtime_tools:
            handlers[name] = make_handler(name)
        return handlers

    def create_loop_executor(
        self,
        *,
        system_prompt: str,
        model: str,
        max_iterations: int,
        max_tokens: int | None = None,
        temperature: float | None = None,
        enabled_tools: set[str] | None = None,
        max_tool_calls: int | None = None,
        max_cumulative_tool_output: int | None = None,
        feature: str = "chatbot",
        verbose_output_dir: str | None = "results",
    ) -> AgentLoopExecutor:
        retry_count, retry_base_delay_sec = self._get_retry_settings()
        client = _ChatbotClientDefaults(
            self._create_openai_client(feature),
            {
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            retry_count=0,
            retry_base_delay_sec=retry_base_delay_sec,
            logger=self.logger,
        )
        return AgentLoopExecutor(
            client=client,
            model=model,
            max_iterations=max_iterations,
            system_prompt=system_prompt,
            tools=self.get_tool_definitions(enabled_tools),
            tool_handlers=self._build_tool_handlers(
                enabled_tools=enabled_tools,
                max_tool_calls=max_tool_calls,
                max_cumulative_tool_output=max_cumulative_tool_output,
            ),
            context_manager=self.state.context_manager,
            plan_manager=self.state.plan_manager,
            memory_store=self.state.memory_store,
            verbose_output_dir=verbose_output_dir,
            llm_retry_count=retry_count,
            llm_retry_base_delay_sec=retry_base_delay_sec,
        )

    def create_loop_state(
        self,
        executor: AgentLoopExecutor,
        task: str,
        checkpoint: Any = None,
    ) -> AgentLoopState:
        self.current_steps = []
        self.last_step = None
        return executor.create_state(
            task,
            checkpoint=checkpoint,
            conversation_history=self.state.conversation_history,
        )

    def step(self, executor: AgentLoopExecutor, state: AgentLoopState) -> AgentLoopStep:
        step = executor.step(state)
        self.state.conversation_history = step.state.conversation_history
        self.last_step = step
        self.current_steps.append(step)
        return step

    def get_intermediate_results(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for step in self.current_steps:
            results.extend(step.tool_results)
        return results

    def create_completion(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        enabled_tools: set[str] | None = None,
        feature: str = "chatbot",
    ) -> dict[str, Any]:
        from ainalyse import load_config
        from ainalyse.ssl_helper import create_openai_client_with_custom_ca

        config = load_config()
        retry_count, retry_base_delay_sec = self._get_retry_settings()
        raw_client = create_openai_client_with_custom_ca(
            config["OPENAI_API_KEY"],
            config["OPENAI_BASE_URL"],
            config.get("CUSTOM_CA_CERT_PATH", ""),
            config.get("CLIENT_CERT_PATH", ""),
            config.get("CLIENT_KEY_PATH", ""),
            feature,
        )
        client = _ChatbotClientDefaults(
            raw_client,
            {
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            retry_count=retry_count,
            retry_base_delay_sec=retry_base_delay_sec,
            logger=self.logger,
        )
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=self.get_tool_definitions(enabled_tools),
            tool_choice="auto",
        )
        return _normalize_completion_payload(response)

    def assistant_message_from_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        return _assistant_message_from_payload(payload)

    def execute_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        enabled_tools: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        tool_messages: list[dict[str, Any]] = []
        for tool_call in tool_calls:
            tool_name = tool_call["name"]
            if enabled_tools is not None and tool_name not in enabled_tools:
                output = f"Error: Tool '{tool_name}' is disabled."
            else:
                output = self.toolbox.execute_named(tool_name, tool_call["arguments"])
            self.state.context_manager.add_tool_result(
                tool_name,
                tool_call["arguments"],
                output,
                tool_call_id=tool_call["id"],
            )
            tool_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "name": tool_name,
                    "content": output,
                }
            )
        return tool_messages

    async def summarize(self, finalize: bool = False) -> str:
        summarizer = ChatbotContextSummarizer(
            summarizer_agent=_create_summarizer_agent(self.state.memory_store),
            toolbox=self.toolbox,
        )
        return await summarizer.summarize(self.state, finalize)


__all__ = [
    "ChatbotAgentState",
    "ChatbotAgent",
    "ChatbotContextSummarizer",
    "TaskStatus",
    "_assistant_message_from_payload",
    "_normalize_completion_payload",
]
