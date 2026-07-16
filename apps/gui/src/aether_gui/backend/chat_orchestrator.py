from __future__ import annotations

import json
from functools import wraps

import ida_kernwin
from aether_utils.config import get_config
from fastmcp.client.client import CallToolResult

from aether_gui.runner import get_shared_worker_manager
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id

from .chat_renderer import ChatbotPanelRenderer
from .chatbot_task import ChatBotTask
from .llm_client import ChatbotClient, LLMResponse, ReasoningDelta, TextDelta, ToolCall, ToolOutput
from .types import ChatPanelProtocol

config = get_config()


class ChatOrchestrator:
    def __init__(
        self, llm_client: ChatbotClient, chatbot_panel: ChatPanelProtocol, mcp_client: MCPClient
    ) -> None:
        self.llm_client = llm_client
        self.chat_renderer = ChatbotPanelRenderer(chatbot_panel)
        self.function_context = None
        self.mcp_client = mcp_client
        self._get_context()

    def _get_context(self) -> None:
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
            args={"rpc_id": rpc_id, "address": hex(current_ea)},
        )
        worker_manager.consume(
            handle,
            on_event=lambda e: self._format_context(e),
            on_error=lambda err: self._run_on_ida_ui_thread(
                lambda: self.chat_renderer.render_error(f"Failed to get IDA context {err}")
            ),
            on_done=None,
        )

    def _format_context(self, tool_result: CallToolResult) -> None:
        if (
            not tool_result.content
            or not tool_result.content[0]
            or tool_result.content[0].type != "text"
        ):
            raise ValueError("Failed to extract text: CallToolResult contains no text data.")

        tool_text = tool_result.content[0].text
        self.function_context = json.loads(tool_text)

    def submit_user_prompt(self, prompt: str) -> None:
        """Called from IDA main thread. Returns immediately."""
        if self.function_context is None:
            self.chat_renderer.render_status("IDA Context was not fetched")
            return

        prompt = prompt.strip()
        if not prompt:
            return

        worker_manager = get_shared_worker_manager()

        self.chat_renderer.render_status("Analyzing current context...")

        task = ChatBotTask()
        handle = worker_manager.submit(
            task,
            llm_client=self.llm_client,
            mcp_url=config.mcp_url,
            user_prompt=prompt,
            ida_context=self.function_context,
        )

        worker_manager.consume(
            handle,
            on_event=lambda e: self._run_on_ida_ui_thread(
                lambda ev=e: self._handle_worker_result(ev)
            ),
            on_error=lambda err: self._run_on_ida_ui_thread(
                lambda: self.chat_renderer.render_error(f"Stream failed: {err}")
            ),
            on_done=None,
        )

    def _handle_worker_result(self, result: LLMResponse) -> None:
        """Render UI and apply IDA actions here"""

        if isinstance(result, (TextDelta, ReasoningDelta)):
            self.chat_renderer.render_aether_message(str(result))
        elif isinstance(result, (ToolCall, ToolOutput)):
            self.chat_renderer.render_tool_message(str(result))

    def _run_on_ida_ui_thread(self, fn) -> None:
        """
        Schedule func back on IDA main UI thread
        """

        @wraps(fn)
        def wrapper() -> int:
            fn()
            return 1

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
