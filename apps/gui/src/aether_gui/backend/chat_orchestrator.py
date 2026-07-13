from __future__ import annotations

import ida_kernwin

from aether_gui.runner import get_shared_worker_manager

from .chat import ChatbotPanelRenderer
from .chatbot_task import ChatBotTask
from .constants import MCP_URL, SYSTEM_PROMPT
from .ida import IDAContextProvider
from .interfaces import ChatPanelProtocol
from .llm import LLMResponse, OpenAIClient, ReasoningDelta, TextDelta, ToolCall, ToolOutput


class ChatOrchestrator:
    def __init__(self, chatbot_panel: ChatPanelProtocol) -> None:

        self.ida_context_provider = IDAContextProvider()
        self.chat_renderer = ChatbotPanelRenderer(chatbot_panel)

    def submit_user_prompt(self, prompt: str) -> None:
        """Called from IDA main thread. Returns immediately."""
        prompt = prompt.strip()
        if not prompt:
            return

        try:
            ida_context = self.ida_context_provider.get_context()
        except Exception as e:
            self.chat_renderer.render_error(f"Failed to collect IDA context: {e}")
            return

        worker_manager = get_shared_worker_manager()

        self.chat_renderer.render_status("Analyzing current context...")

        llm_client = OpenAIClient(SYSTEM_PROMPT)
        task = ChatBotTask(
            llm_client=llm_client,
            mcp_url=MCP_URL,
            user_prompt=prompt,
            ida_context=ida_context,
        )
        handle = worker_manager.submit(task)

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

        match result:
            case TextDelta() | ReasoningDelta():
                self.chat_renderer.render_aether_message(result.output_string)

            case ToolCall() | ToolOutput():
                self.chat_renderer.render_tool_message(result.output_string)

    def _run_on_ida_ui_thread(self, fn) -> None:
        """
        Schedule func back on IDA main UI thread
        """

        def wrapper() -> int:
            fn()
            return 1

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
