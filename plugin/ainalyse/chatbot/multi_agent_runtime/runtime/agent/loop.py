from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


def _parse_xml_tool_calls(content: str) -> list[dict[str, Any]]:
    """
    Fallback parser for XML-style tool calls.
    Supports formats like:
    <tool_call>
    <function=func_name>
    <parameter=param1>value1</parameter>
    </function>
    </tool_call>
    """
    if not content or "<tool_call>" not in content:
        return []

    tool_calls = []
    # Regex to find each <tool_call>...</tool_call> block
    call_blocks = re.findall(r"<tool_call>([\s\S]*?)</tool_call>", content)
    
    for block in call_blocks:
        # 1. Try to find function name
        func_match = re.search(r"<function=([a-zA-Z0-9_]+)>", block)
        if not func_match:
            # Try to see if the block itself is a JSON object
            try:
                data = json.loads(block.strip())
                if isinstance(data, dict) and "name" in data:
                    tool_calls.append({
                        "id": f"xml_{time.time_ns()}",
                        "type": "function",
                        "function": {
                            "name": data["name"],
                            "arguments": json.dumps(data.get("arguments", {}))
                        }
                    })
                continue
            except Exception:
                continue

        func_name = func_match.group(1)
        arguments = {}
        
        # 2. Extract parameters
        param_matches = re.findall(r"<parameter=([a-zA-Z0-9_]+)>([\s\S]*?)</parameter>", block)
        for param_name, param_value in param_matches:
            arguments[param_name] = param_value.strip()
            
        tool_calls.append({
            "id": f"xml_{time.time_ns()}",
            "type": "function",
            "function": {
                "name": func_name,
                "arguments": json.dumps(arguments)
            }
        })
        
    return tool_calls


def _collect_reasoning_values(message: Any) -> list[Any]:
    candidates = []
    for attr_name in ("reasoning", "reasoning_content", "reasoning_details"):
        if hasattr(message, attr_name):
            value = getattr(message, attr_name)
            if value:
                candidates.append(value)
    if hasattr(message, "model_dump"):
        try:
            dumped = message.model_dump()
            for key in ("reasoning", "reasoning_content", "reasoning_details"):
                value = dumped.get(key)
                if value:
                    candidates.append(value)
        except Exception:
            pass
    return candidates


def extract_reasoning_trace(message: Any) -> str:
    rendered = []
    for value in _collect_reasoning_values(message):
        if isinstance(value, str):
            item = value
        else:
            item = json.dumps(value, indent=2, default=str)
        if item and item not in rendered:
            rendered.append(item)
    return "\n\n".join(rendered)


def extract_reasoning_text(message: Any) -> str:
    parts: list[str] = []
    for value in _collect_reasoning_values(message):
        if isinstance(value, str):
            if value.strip():
                parts.append(value.strip())
        elif isinstance(value, dict):
            for key in ("text", "summary", "content"):
                text = value.get(key)
                if text:
                    parts.append(str(text).strip())
                    break
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    text = item.get("text") or item.get("summary") or item.get("content")
                    if text:
                        parts.append(str(text).strip())
                else:
                    text = str(item).strip()
                    if text:
                        parts.append(text)
    return "\n\n".join(dict.fromkeys(part for part in parts if part))


@dataclass
class AgentLoopState:
    task: str
    checkpoint: Any = None
    conversation_history: list[dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    tool_calls_made: list[dict[str, Any]] = field(default_factory=list)
    final_analysis: str = ""
    done: bool = False
    missed_tool_call_count: int = 0


@dataclass
class AgentLoopStep:
    state: AgentLoopState
    messages: list[dict[str, Any]] = field(default_factory=list)
    assistant_message: dict[str, Any] | None = None
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    final_analysis: str = ""
    done: bool = False


class AgentLoopExecutor:
    def __init__(
        self,
        client: Any,
        model: str,
        max_iterations: int,
        system_prompt: str,
        tools: list[dict[str, Any]],
        tool_handlers: dict[str, Any],
        context_manager: Any,
        plan_manager: Any,
        memory_store: Any,
        track_file_callback: Any = None,
        verbose_output_dir: str = "results",
        copy_reasoning_to_content: bool = False,
        llm_retry_count: int = 2,
        llm_retry_base_delay_sec: float = 1.0,
    ):
        self.client = client
        self.model = model
        self.max_iterations = max_iterations
        self.system_prompt = system_prompt
        self.tools = tools
        self.tool_handlers = tool_handlers
        self.context_manager = context_manager
        self.plan_manager = plan_manager
        self.memory_store = memory_store
        self.track_file_callback = track_file_callback
        self.verbose_output_dir = verbose_output_dir
        self.copy_reasoning_to_content = copy_reasoning_to_content
        self.llm_retry_count = max(0, int(llm_retry_count))
        self.llm_retry_base_delay_sec = max(0.0, float(llm_retry_base_delay_sec))
        self.logger = logging.getLogger(__name__)

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

    def _create_completion_with_retry(self, **request: Any) -> Any:
        attempts = self.llm_retry_count + 1
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                return self.client.chat.completions.create(**request)
            except Exception as exc:
                last_error = exc
                if attempt >= attempts or not self._is_retryable_error(exc):
                    raise
                delay_seconds = self.llm_retry_base_delay_sec * (2 ** (attempt - 1))
                self.logger.warning(
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

    def _format_verbose_conversation_history(self, messages: list[dict[str, Any]]) -> str:
        lines: list[str] = []
        for index, message in enumerate(messages, start=1):
            lines.append(f"[{index}] role={message.get('role', '')}")
            if "tool_call_id" in message:
                lines.append(f"tool_call_id: {message.get('tool_call_id', '')}")
            if "name" in message:
                lines.append(f"name: {message.get('name', '')}")
            if "tool_calls" in message:
                lines.append("tool_calls:")
                lines.append(json.dumps(message.get("tool_calls", []), indent=2, ensure_ascii=False, default=str))
            lines.append("content:")
            lines.append(str(message.get("content", "")))
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def _format_verbose_assistant_response(self, assistant_message: Any) -> str:
        lines = ["", "=== ASSISTANT RESPONSE ==="]
        if hasattr(assistant_message, "model_dump"):
            dumped = assistant_message.model_dump()
        else:
            dumped = {
                "role": getattr(assistant_message, "role", "assistant"),
                "content": getattr(assistant_message, "content", ""),
            }
            if getattr(assistant_message, "tool_calls", None):
                dumped["tool_calls"] = assistant_message.tool_calls

        lines.append(f"role: {dumped.get('role', 'assistant')}")
        if dumped.get("tool_calls"):
            lines.append("tool_calls:")
            lines.append(json.dumps(dumped.get("tool_calls", []), indent=2, ensure_ascii=False, default=str))
        lines.append("content:")
        content = str(dumped.get("content", "") or "")
        lines.append(content)

        reasoning_trace = extract_reasoning_trace(assistant_message)
        if reasoning_trace and reasoning_trace.strip() != content.strip():
            lines.append("")
            lines.append("reasoning_trace:")
            lines.append(reasoning_trace)

        return "\n".join(lines).rstrip() + "\n"

    def _write_verbose_prompt_log(self, state: AgentLoopState, messages: list[dict[str, Any]], assistant_message: Any = None) -> str | None:
        try:
            os.makedirs(self.verbose_output_dir, exist_ok=True)
            now = datetime.now()
            date_part = now.strftime("%Y%m%d")
            timestamp_part = now.strftime("%H%M%S_%f")
            filepath = os.path.join(
                self.verbose_output_dir,
                f"iter_{state.iteration:03d}_{date_part}_{timestamp_part}.txt",
            )
            with open(filepath, "w", encoding="utf-8") as handle:
                handle.write(self._format_verbose_conversation_history(messages))
                if assistant_message is not None:
                    handle.write(self._format_verbose_assistant_response(assistant_message))
            return filepath
        except Exception:
            # Verbose logging is best-effort and should never break the chat loop.
            return None

    def _append_verbose_step_state(
        self,
        filepath: str | None,
        state: AgentLoopState,
        tool_results: list[dict[str, Any]] | None = None,
    ) -> None:
        if not filepath:
            return
        try:
            with open(filepath, "a", encoding="utf-8") as handle:
                handle.write("\n\n=== STORED CONVERSATION HISTORY AFTER STEP ===\n")
                handle.write(f"iteration: {state.iteration}\n")
                handle.write(f"done: {state.done}\n")
                handle.write(f"final_analysis_len: {len(state.final_analysis or '')}\n")
                handle.write(f"tool_results_this_step: {len(tool_results or [])}\n\n")
                handle.write(self._format_verbose_conversation_history(state.conversation_history))
        except Exception:
            pass

    def _should_track_file_read(self, tool_name: str, args: dict[str, Any], result: str) -> bool:
        return tool_name == "get_file_content" and "file_path" in args and result and not result.startswith("File not found:")

    def _build_history_assistant_message(self, assistant_message: Any) -> dict[str, Any]:
        reasoning_text = extract_reasoning_text(assistant_message)
        if hasattr(assistant_message, "model_dump"):
            dumped = assistant_message.model_dump()
            msg_dict = {
                "role": dumped.get("role", "assistant"),
                "content": dumped.get("content") or "",
            }
            if dumped.get("tool_calls"):
                msg_dict["tool_calls"] = dumped["tool_calls"]
        else:
            msg_dict = {"role": "assistant", "content": getattr(assistant_message, "content", "")}
            if getattr(assistant_message, "tool_calls", None):
                msg_dict["tool_calls"] = assistant_message.tool_calls
        if not msg_dict.get("tool_calls"):
            msg_dict.pop("tool_calls", None)
        if self.copy_reasoning_to_content and reasoning_text:
            msg_dict["content"] = reasoning_text
        elif not (msg_dict.get("content") or "") and reasoning_text:
            msg_dict["content"] = reasoning_text
        return msg_dict

    def execute_tool(self, tool_call: Any) -> str:
        function = tool_call.function if hasattr(tool_call, "function") else tool_call["function"]
        tool_name = function.name if hasattr(function, "name") else function["name"]
        arguments = function.arguments if hasattr(function, "arguments") else function["arguments"]
        if tool_name not in self.tool_handlers:
            return f"Error: Unknown tool '{tool_name}'"
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
            result = self.tool_handlers[tool_name](**args)
            self.context_manager.add_tool_result(tool_name, args, result, tool_call_id=getattr(tool_call, "id", ""))
            if self.track_file_callback and self._should_track_file_read(tool_name, args, result):
                self.track_file_callback(args["file_path"])
            return result
        except Exception as exc:
            return f"Error executing {tool_name}: {exc}"

    def create_state(
        self,
        task: str,
        checkpoint: Any = None,
        conversation_history: list[dict[str, Any]] | None = None,
    ) -> AgentLoopState:
        return AgentLoopState(
            task=task,
            checkpoint=checkpoint,
            conversation_history=[] if conversation_history is None else conversation_history,
        )

    def _empty_client_step(self, state: AgentLoopState) -> AgentLoopStep:
        state.done = True
        state.final_analysis = "No LLM client configured."
        return AgentLoopStep(
            state=state,
            final_analysis=state.final_analysis,
            done=True,
        )

    def step(self, state: AgentLoopState | None = None, *, task: str | None = None, checkpoint: Any = None) -> AgentLoopStep:
        if state is None:
            if task is None:
                raise ValueError("step() requires either an AgentLoopState or a task.")
            state = self.create_state(task, checkpoint)

        if state.done:
            return AgentLoopStep(
                state=state,
                final_analysis=state.final_analysis,
                done=True,
            )

        if self.client is None:
            return self._empty_client_step(state)

        # max_iterations < 0 means no iteration cap.
        if self.max_iterations >= 0 and state.iteration >= self.max_iterations:
            state.done = True
            if not state.final_analysis:
                state.final_analysis = f"Maximum iterations ({self.max_iterations}) reached."
            if self.plan_manager:
                self.plan_manager.clear()
            return AgentLoopStep(
                state=state,
                final_analysis=state.final_analysis,
                done=True,
            )

        state.iteration += 1
        assembled = self.context_manager.assemble_prompt(
            system_prompt=self.system_prompt,
            conversation_history=state.conversation_history,
            checkpoint=state.checkpoint,
            current_task=state.task if state.iteration == 1 else "",
            plan=getattr(self.plan_manager, "active_plan", None),
        )
        state.conversation_history = assembled.conversation_history
        response = self._create_completion_with_retry(
            model=self.model,
            messages=assembled.messages,
            tools=self.tools,
            tool_choice="auto",
        )
        assistant_message = response.choices[0].message
        verbose_filepath = self._write_verbose_prompt_log(state, assembled.messages, assistant_message)

        # Detect tool calls (Native API or Fallback XML)
        raw_tool_calls = getattr(assistant_message, "tool_calls", []) or []
        if not raw_tool_calls:
            # Fallback for models that output raw XML in content
            content = getattr(assistant_message, "content", "") or ""
            raw_tool_calls = _parse_xml_tool_calls(content)

        history_message = self._build_history_assistant_message(assistant_message)
        # If we used fallback XML, we must simulate the tool_calls field in history
        if not history_message.get("tool_calls") and raw_tool_calls:
            history_message["tool_calls"] = raw_tool_calls

        state.conversation_history.append(history_message)

        tool_results: list[dict[str, Any]] = []
        if raw_tool_calls:
            state.missed_tool_call_count = 0  # Reset on successful tool call
            for tool_call in raw_tool_calls:
                tool_result = self.execute_tool(tool_call)
                function = tool_call.function if hasattr(tool_call, "function") else tool_call["function"]
                tool_name = function.name if hasattr(function, "name") else function["name"]
                arguments = function.arguments if hasattr(function, "arguments") else function["arguments"]
                if isinstance(arguments, str):
                    try:
                        parsed_arguments = json.loads(arguments)
                    except Exception:
                        parsed_arguments = arguments
                else:
                    parsed_arguments = arguments
                tool_record = {"name": tool_name, "arguments": parsed_arguments, "result": tool_result}
                state.tool_calls_made.append(tool_record)
                tool_results.append(
                    {
                        "name": tool_name,
                        "arguments": parsed_arguments,
                        "result": tool_result,
                        "tool_call_id": getattr(tool_call, "id", ""),
                    }
                )
                state.conversation_history.append(
                    {
                        "role": "tool",
                        "content": tool_result,
                        "tool_call_id": getattr(tool_call, "id", ""),
                    }
                )
            self._append_verbose_step_state(verbose_filepath, state, tool_results)
            return AgentLoopStep(
                state=state,
                messages=assembled.messages,
                assistant_message=history_message,
                tool_results=tool_results,
                done=False,
            )

        state.final_analysis = getattr(assistant_message, "content", "") or extract_reasoning_text(assistant_message)

        # Mandatory Loop Continuation: If there is an active plan that is not yet complete,
        # we must continue the loop even if the LLM did not call a tool in this turn.
        # This allows the Agent to fulfill its mandate of sequential task execution.
        state.done = True
        if self.plan_manager:
            active_plan = getattr(self.plan_manager, "active_plan", None)
            if active_plan and not active_plan.is_complete():
                state.missed_tool_call_count += 1
                if state.missed_tool_call_count <= 1:
                    self.logger.info("Plan is active and incomplete; providing feedback and continuing loop.")
                    state.done = False
                    # Insert feedback as a system message to guide the agent
                    state.conversation_history.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM_ADVICE] You have an active Action Plan with pending tasks. "
                            "If you have completed your investigation, you MUST use the remove_action_plan tool. "
                            "Otherwise, you MUST call a tool to continue your implementation of the plan. "
                            "Do not provide a final answer until the Action Plan is empty."
                        )
                    })
                else:
                    self.logger.info("Plan is active but agent failed to act twice; concluding and clearing plans.")
                    state.done = True
                    if self.plan_manager:
                        self.plan_manager.clear()

        self._append_verbose_step_state(verbose_filepath, state, tool_results)
        return AgentLoopStep(
            state=state,
            messages=assembled.messages,
            assistant_message=history_message,
            final_analysis=state.final_analysis,
            done=state.done,
        )

    def run(self, task: str, checkpoint: Any = None) -> dict[str, Any]:
        if self.client is None:
            return {
                "task": task,
                "iterations": 0,
                "tool_calls": [],
                "final_analysis": "No LLM client configured.",
                "context_stats": self.context_manager.get_statistics(),
                "plan_stats": self.plan_manager.summary() if hasattr(self.plan_manager, "summary") else None,
            }

        state = self.create_state(task, checkpoint)
        while not state.done and (self.max_iterations < 0 or state.iteration < self.max_iterations):
            self.step(state)

        return {
            "task": task,
            "iterations": state.iteration,
            "tool_calls": state.tool_calls_made,
            "final_analysis": state.final_analysis,
            "context_stats": self.context_manager.get_statistics(),
            "plan_stats": self.plan_manager.summary() if hasattr(self.plan_manager, "summary") else None,
        }
