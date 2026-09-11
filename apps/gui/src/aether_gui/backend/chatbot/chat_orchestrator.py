from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import Future
from functools import wraps
from typing import Any

import ida_kernwin
from aether_gui.runner import get_shared_worker_manager
from aether_gui.runner.types import TaskHandle
from aether_gui.utils.chat_session import ChatSession
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.config import get_config
from fastmcp.client.client import CallToolResult

from .renderer import ChatAreaProtocol, ChatbotAreaRenderer, MessageType
from .task import ChatBotTask, LLMResponse, ReasoningDelta, TextDelta, ToolCall, ToolOutput

config = get_config()


class ChatOrchestrator:
    def __init__(
        self,
        chatbot_panel: ChatAreaProtocol,
        mcp_client: MCPClient,
        session: ChatSession,
        *,
        on_turn_started: Callable[[], None] = lambda: None,
        on_turn_finished: Callable[[], None] = lambda: None,
    ) -> None:
        self.chat_renderer = ChatbotAreaRenderer(chatbot_panel)
        self.function_context = None
        self.mcp_client = mcp_client
        self.handles: list[TaskHandle] = []
        self.prompt: str | None = None
        self.session = session
        self._turn_active = False
        self._closed = False
        self.on_turn_started = on_turn_started
        self.on_turn_finished = on_turn_finished

    def _get_context(self) -> Future[dict[str, Any]]:
        current_ea = ida_kernwin.get_screen_ea()
        rpc_id = get_rpc_id()
        if rpc_id is None:
            self.chat_renderer.render_error("RPC server does not exist")
            raise Exception("RPC server does not exist")

        task = CallToolTask()
        worker_manager = get_shared_worker_manager()

        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="get_function_context",
            tool_args={"rpc_id": rpc_id, "address": hex(current_ea)},
        )
        self.handles.append(handle)

        fut: Future[dict[str, Any]] = Future()

        def on_error(error: BaseException) -> None:
            if not fut.done():
                fut.set_exception(error)

        def on_done() -> None:
            if not fut.done():
                fut.set_exception(ValueError("IDA context request returned no result"))

        worker_manager.consume(
            handle,
            on_event=lambda e: self._format_context(e, fut),
            on_error=on_error,
            on_done=on_done,
        )
        return fut

    def _format_context(self, tool_result: CallToolResult, future: Future[dict[str, Any]]) -> None:
        if future.done():
            return
        if (
            not tool_result.content
            or not tool_result.content[0]
            or tool_result.content[0].type != "text"
        ):
            future.set_exception(ValueError("CallToolResult contains no text data"))
            return
        future.set_result(json.loads(tool_result.content[0].text))

    def submit_user_prompt(self, prompt: str) -> None:
        """Called from IDA main thread. Returns immediately."""
        if self._turn_active:
            return

        ida_context = self._get_context()

        self.prompt = prompt.strip()
        if not self.prompt:
            return

        self._set_turn_active(True)

        worker_manager = get_shared_worker_manager()

        task = ChatBotTask()
        handle = worker_manager.submit(
            task,
            ida_context=ida_context,
            mcp_client=self.mcp_client,
            user_prompt=self.prompt,
            session=self.session,
        )
        self.handles.append(handle)

        handler = self._handle_worker_result()
        worker_manager.consume(
            handle,
            on_event=lambda e: self._run_on_ida_ui_thread(lambda ev=e: handler(ev)),
            on_error=lambda err: self._run_on_ida_ui_thread(
                lambda: (
                    self.chat_renderer.render_error(f"Stream failed: {err}")
                    and self._set_turn_active(False)
                )
            ),
            on_done=lambda: self._run_on_ida_ui_thread(lambda: self._set_turn_active(False)),
        )

    def _set_turn_active(self, active: bool) -> None:
        """Track whether a turn is streaming and fire the matching hook."""

        self._turn_active = active
        if active:
            self.on_turn_started()
        else:
            self.on_turn_finished()

    def _handle_worker_result(self) -> Callable[[LLMResponse], None]:
        """Render UI and apply IDA actions here"""
        last_message_type: MessageType = "text"
        message_created: bool = False

        def _call_renderer(result: LLMResponse) -> None:
            nonlocal last_message_type, message_created
            current_type = last_message_type
            current_created = message_created
            if isinstance(result, (TextDelta, ReasoningDelta)):
                if str(result) != "":
                    last_message_type = "text"
                    message_created = True
                    self.chat_renderer.render_aether_message(
                        str(result), current_type, message_created=current_created
                    )
            elif isinstance(result, (ToolCall, ToolOutput)):
                last_message_type = "tool"
                message_created = True
                self.chat_renderer.render_tool_message(str(result), message_created=current_created)

        return _call_renderer

    def _run_on_ida_ui_thread(self, fn: Callable[..., Any]) -> None:
        """
        Schedule func back on IDA main UI thread
        """

        @wraps(fn)
        def wrapper() -> int:
            if not self._closed:
                fn()
            return 1

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)

    def shutdown(self) -> None:
        worker_manager = get_shared_worker_manager()
        self._closed = True
        self._turn_active = False
        for handle in self.handles:
            worker_manager.cancel(handle.task_id)
        self.handles.clear()
