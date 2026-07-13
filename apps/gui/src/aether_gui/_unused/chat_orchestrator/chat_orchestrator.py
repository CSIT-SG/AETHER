from __future__ import annotations

import threading
import traceback

import ida_kernwin
from aether_gui.utils.async_runner import AsyncRunner

from .helper import (
    ChatbotPanelRenderer,
    IDAContext,
    IDAContextProvider,
    LLMResponse,
    ReasoningDelta,
    TextDelta,
    ToolCall,
    ToolOutput,
    WorkerManager,
    WorkerTask,
)


class ChatOrchestrator:
    def __init__(
        self,
        ida_context_provider: IDAContextProvider,
        worker_manager: WorkerManager,
        chat_render: ChatbotPanelRenderer,
        async_runner: AsyncRunner,
    ) -> None:

        self.ida_context_provider = ida_context_provider
        self.worker_manager = worker_manager
        self.chat_renderer = chat_render
        self.async_runner = async_runner

    def submit_user_prompt(self, prompt: str) -> None:
        """
        Synchronous handler to be called from ChatInput submit btn
        """
        prompt = prompt.strip()

        if not prompt:
            return

        try:
            ida_context = self.ida_context_provider.get_context()
        except Exception as e:
            self.chat_renderer.render_error(f"Failed to collect IDA context: {e}")
            return

        task = self._build_worker_task(
            user_prompt=prompt,
            ida_context=ida_context,
        )

        self.chat_renderer.render_status("Analyzing current context...")

        threading.Thread(target=self._consume_stream, args=(task,), daemon=True).start()

    def _consume_stream(self, task: WorkerTask) -> None:
        try:
            for event in self.async_runner.submit_stream(lambda: self.worker_manager.submit(task)):
                # Capture event in default arg to avoid late-binding
                self._run_on_ida_ui_thread(lambda e=event: self._handle_worker_result(e))
        except Exception:
            traceback.print_exc()
            self._run_on_ida_ui_thread(
                lambda: self.chat_renderer.render_error("Could not finish stream from OpenRouter")
            )

    def _handle_worker_result(self, result: LLMResponse) -> None:
        """Render UI and apply IDA actions here"""

        match result:
            case TextDelta() | ReasoningDelta():
                self.chat_renderer.render_aether_message(result.output_string)

            case ToolCall() | ToolOutput():
                self.chat_renderer.render_tool_message(result.output_string)

    def _build_worker_task(self, user_prompt: str, ida_context: IDAContext) -> WorkerTask:
        return {
            "user_prompt": user_prompt,
            "ida_context": ida_context,
        }

    def _run_on_ida_ui_thread(self, fn) -> None:
        """
        Schedule func back on IDA main UI thread
        """

        def wrapper() -> int:
            fn()
            return 1

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
