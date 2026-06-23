import asyncio
import html
import json
import os
import re
from datetime import datetime

import ida_kernwin

from ainalyse.async_manager import cancel_pipeline, start_pipeline, use_async_worker
from ainalyse.qt_shim import QtCore, QtGui, QtWidgets, is_deleted

from .. import finalize_prompt, get_data_directory, load_config
from .backend.toolconfig import TOOL_CONFIG
from .chatbot_agent import ChatbotAgent, TaskStatus
from .chatbot_ida.toolset import CHATBOT_TOOL_REGISTRY as TOOL_REGISTRY
from .chatbot_ida.toolset import ToolNames
from .context_menu_controller import ClearChatHistory, SearchText, SelectBinaryFunctionsContext, SelectExposedTools, StopCurrentPrompt
from .logging_utils import get_chatbot_logger

BASE_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "base_chat.txt")
VERBOSE_OUTPUT_ROOT = os.path.join(get_data_directory(), "chatbot", "verbose")
CONVO_LIMIT = 10
MAX_CONTEXT_FUNCTIONS = 50
MAX_TOOL_CALLS = 10


class ChatbotController:
    def __init__(self):
        self.logger = get_chatbot_logger("chatbot.controller")
        config = load_config()
        self.max_tokens = config.get("CHATBOT_MAX_TOKENS", 128000)  # Increased from 65536 to 128000 for chatbot tool calls

        self.PERSISTENT_CHATBOT_AGENT = ChatbotAgent()
        self.PERSISTENT_MESSAGE_LOG = []

        self.parent = None
        self.main_widget = None
        self.history_view = None
        self.input_box = None
        self.context_frame = None
        self.context_gear_btn = None
        self.pills_scroll = None
        self.pills_container = None
        self.pills_layout = None
        self.search_bar = None

        self.base_prompt = self._load_base_prompt()
        self.chatbot_agent = self.PERSISTENT_CHATBOT_AGENT
        self.agent_state = self.chatbot_agent.state
        self.agent_state.context["specialist_progress_notifier"] = self._notify_specialist_progress
        self.is_thinking = False
        self.force_stop = False
        self.stop_generation = 0
        self._is_terminating = False
        self._worker_loop = None

        # Worker-owned asyncio queue. UI/main-thread producers enqueue via
        # call_soon_threadsafe onto the worker loop.
        self.message_queue = asyncio.Queue()
        self.is_running = True
        self.exposed_tools = {name for name, is_enabled in TOOL_CONFIG.items() if is_enabled}
        session = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.verbose_output_dir = os.path.join(VERBOSE_OUTPUT_ROOT, "agent_loop", session)
        self.logger.info(
            "Initialized chatbot controller max_tokens=%s base_prompt_len=%s verbose_dir=%s",
            self.max_tokens,
            len(self.base_prompt),
            self.verbose_output_dir,
        )

        self.theme_filter = None
        self._theme_refresh_pending = False
        self._is_applying_theme = False

        self.manual_context = []
        self.current_match_idx = 0
        self.total_matches = 0
        self._pipeline_retry_attempts = 0
        self._pipeline_retry_limit = 15
        self.active_agent = "AETHER"
        self._pending_delegate_tool_rendered = False

    def bind_widgets(
        self,
        parent,
        main_widget,
        history_view,
        input_box,
        context_frame,
        context_gear_btn,
        pills_scroll,
        pills_container,
        pills_layout,
        search_bar,
    ):
        self.parent = parent
        self.main_widget = main_widget
        self.history_view = history_view
        self.input_box = input_box
        self.context_frame = context_frame
        self.context_gear_btn = context_gear_btn
        self.pills_scroll = pills_scroll
        self.pills_container = pills_container
        self.pills_layout = pills_layout
        self.search_bar = search_bar

    def _load_base_prompt(self):
        try:
            with open(BASE_PROMPT_PATH, encoding="utf-8") as f:
                f_string_code = 'f"""' + f.read() + '"""'
                safe_globals = {
                    "ToolNames": ToolNames,
                    "TaskStatus": TaskStatus,
                }
                return eval(f_string_code, safe_globals, {})
        except Exception as e:
            self.logger.exception("Error loading base prompt: %s", e)
            return "You are a helpful reverse engineering assistant."

    # def _on_context_gear_clicked(self):
    #     self._select_binary_functions_context()

    # for themes
    # refactor into new file
    def _apply_theme_styles(self):
        """Apply theme-aware styles based on the active Qt palette."""
        if not self.main_widget or is_deleted(self.main_widget):
            return
        self._is_applying_theme = True
        try:
            palette = self.main_widget.palette()

            window_color = palette.color(QtGui.QPalette.Window).name()
            button_color = palette.color(QtGui.QPalette.Button).name()
            base_color = palette.color(QtGui.QPalette.Base).name()
            text_color = palette.color(QtGui.QPalette.Text).name()
            mid_color = palette.color(QtGui.QPalette.Mid).name()

            # Detect dark mode
            text_qcolor = palette.color(QtGui.QPalette.Text)
            is_dark_mode = text_qcolor.lightness() > 128

            # Smart colors based on mode
            if is_dark_mode:
                context_bg = palette.color(QtGui.QPalette.Button).name()
                hover_bg = palette.color(QtGui.QPalette.Button).lighter(120).name()
            else:
                context_bg = "#f5f5f5"  # Original light mode color
                hover_bg = "#e0e0e0"

            if self.context_frame and not is_deleted(self.context_frame):
                self.context_frame.setStyleSheet(f"""
                    QFrame {{
                        background: {context_bg};
                        border: 1px solid {mid_color};
                        border-radius: 8px;
                        padding: 4px 8px;
                    }}
                """)

            if self.context_gear_btn and not is_deleted(self.context_gear_btn):
                # Only apply color-related changes to the gear button to avoid breaking its layout
                self.context_gear_btn.setStyleSheet(f"""
                    QPushButton {{
                        font-size: 16pt;
                        font-weight: bold;
                        color: {text_color};
                        border: none;
                        padding: -2px 0px 2px 0px;
                        margin: 0px;
                        background: transparent;
                        height: 28px;
                        width: 28px;
                        min-height: 28px;
                        min-width: 28px;
                        line-height: 28px;
                        text-align: center;
                    }}
                    QPushButton:hover {{
                        background-color: {hover_bg};
                        border-radius: 4px;
                    }}
                """)

            if self.pills_scroll and not is_deleted(self.pills_scroll):
                self.pills_scroll.setStyleSheet("background: transparent;")
                self.pills_scroll.verticalScrollBar().setStyleSheet(f"""
                    QScrollBar:vertical {{
                        border: none;
                        background: transparent;
                        width: 8px;
                        border-radius: 4px;
                        margin: 0px;
                    }}
                    QScrollBar::handle:vertical {{
                        background: {mid_color};
                        min-height: 20px;
                        border-radius: 4px;
                    }}
                    QScrollBar::handle:vertical:hover {{
                        background: {hover_bg};
                    }}
                    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                        height: 0px;
                        background: none;
                    }}
                    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                        background: none;
                    }}
                """)

            if self.search_bar is not None and not is_deleted(self.search_bar):
                self.search_bar.apply_theme_styles(
                    window_color=window_color,
                    base_color=base_color,
                    text_color=text_color,
                    mid_color=mid_color,
                )
        finally:
            self._is_applying_theme = False

    def _build_pill_stylesheet(self, palette):
        mid_color = palette.color(QtGui.QPalette.Mid).name()
        text_color = palette.color(QtGui.QPalette.Text).name()
        return f"""
            QPushButton {{
                border: 1px solid {mid_color};
                border-radius: 12px;
                background: transparent;
                padding: 4px 12px;
                color: {text_color};
                font-size: 10pt;
            }}
            QPushButton:hover {{
                background: #d32f2f;
                color: white;
            }}
        """

    def _restyle_existing_context_pills(self):
        if not self.main_widget:
            return
        palette = self.main_widget.palette()
        pill_style = self._build_pill_stylesheet(palette)
        for i in range(self.pills_layout.count()):
            item = self.pills_layout.itemAt(i)
            widget = item.widget() if item else None
            if isinstance(widget, QtWidgets.QPushButton):
                widget.setStyleSheet(pill_style)

    def _install_theme_refresh_hook(self):
        """Install an application-level filter to detect theme/palette updates."""
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        from ainalyse.chatbot.ui.viewer import ThemeRefreshEventFilter

        self.theme_filter = ThemeRefreshEventFilter(self._schedule_theme_refresh)
        app.installEventFilter(self.theme_filter)

    def _schedule_theme_refresh(self):
        """Coalesce rapid theme events into one style refresh."""
        if self._theme_refresh_pending or self._is_applying_theme:
            return
        self._theme_refresh_pending = True
        QtCore.QTimer.singleShot(0, self._run_theme_refresh)

    def _run_theme_refresh(self):
        self._theme_refresh_pending = False
        if not self.main_widget or is_deleted(self.main_widget) or self._is_applying_theme:
            return
        self._apply_theme_styles()
        self._restyle_existing_context_pills()

    # themes end

    def _refresh_context_pills(self):
        palette = self.main_widget.palette()
        pill_style = self._build_pill_stylesheet(palette)

        for i in reversed(range(self.pills_layout.count())):
            widget = self.pills_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        if len(self.manual_context) > MAX_CONTEXT_FUNCTIONS:
            warning_label = QtWidgets.QLabel(f"!! Too many functions selected ({len(self.manual_context)}). Unable to display.")
            warning_label.setStyleSheet("color: red; font-weight: bold;")
            self.pills_layout.addWidget(warning_label)
            return

        for idx, func in enumerate(self.manual_context):
            pill = QtWidgets.QPushButton(str(func["name"]))
            pill.setStyleSheet(pill_style)
            pill.setCursor(QtCore.Qt.PointingHandCursor)
            pill.clicked.connect(lambda checked, idx=idx: self._remove_context_pill(idx))
            self.pills_layout.addWidget(pill)
            print(f"[AETHER Manual Context Setter] [{idx + 1}/{len(self.manual_context)}] In : '{func['name']}' at [{func['address']}]")

    def _remove_context_pill(self, idx):
        if 0 <= idx < len(self.manual_context):
            print(f"[AETHER Manual Context Setter] Function removed from context: '{self.manual_context[idx]['name']}'")
            del self.manual_context[idx]
            self._refresh_context_pills()

    def _scroll_to_bottom(self):
        if not self._ui_is_available():
            return
        cursor = self.history_view.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.history_view.setTextCursor(cursor)

    def _render_message(self, sender, message, is_html=False):
        if not self._ui_is_available():
            return
        msg = message.rstrip()
        if not is_html:
            msg = html.escape(msg)
        full_html = f"""
        <table width='100%' style='margin-bottom: 15px;'>
            <tr>
                <td width='1%' style='vertical-align: top; white-space: nowrap; padding-right: 5px;'>
                    <b>{sender}:</b>
                </td>
                <td width='79%' style='vertical-align: top;'>
                    <div style='font-family: monospace; white-space: pre-wrap; word-wrap: break-word;'>{msg}</div>
                </td>
                <td width='20%'></td>
            </tr>
        </table>
        """
        self.history_view.append(full_html)
        self._scroll_to_bottom()

    def _add_message(self, sender, message, is_html=False):
        if not self._ui_is_available():
            return
        self.PERSISTENT_MESSAGE_LOG.append({"sender": sender, "msg": message})
        self._render_message(sender, message, is_html)

    def _ui_is_available(self) -> bool:
        if self._is_terminating or self.history_view is None:
            return False
        return not is_deleted(self.history_view)

    def _add_message_threadsafe(self, sender, message, is_html=False):
        """Ensure UI message updates always run on IDA/Qt main thread."""
        app = QtWidgets.QApplication.instance()
        if app is not None and QtCore.QThread.currentThread() == app.thread():
            self._add_message(sender, message, is_html)
            return

        def sync_add():
            self._add_message(sender, message, is_html)
            return 1

        self._safe_execute_sync(sync_add, ida_kernwin.MFF_WRITE)

    def _safe_execute_sync(self, func, flags):
        """Wrapper for execute_sync that checks for shutdown to avoid crashes."""
        if self._is_terminating:
            return -1
        
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return -1

        return ida_kernwin.execute_sync(func, flags)

    def _enqueue_packet(self, packet):
        """Enqueue a packet from UI/main thread into the worker-owned asyncio queue."""
        if self._is_terminating:
            return

        loop = self._worker_loop
        if loop and loop.is_running():
            try:
                loop.call_soon_threadsafe(self.message_queue.put_nowait, packet)
                return
            except RuntimeError:
                # Loop is shutting down; fall back to local enqueue before restart.
                pass
        self.message_queue.put_nowait(packet)

    def send_message(self):
        if self._is_terminating:
            return

        config = load_config()
        self.max_tokens = config.get("CHATBOT_MAX_TOKENS", 128000)

        user_message = self.input_box.toPlainText().strip()
        if not user_message:
            return

        is_interrupt = self.is_thinking
        self._add_message("You", user_message)
        self.input_box.clear()
        self.force_stop = False
        self.is_running = True
        self._enqueue_packet(
            {
                "type": "user_input",
                "content": self._settle_manual_context() + user_message,
                "is_interrupt": is_interrupt,
            }
        )
        self.manual_context.clear()
        self._refresh_context_pills()
        if not self.is_thinking:
            self._trigger_agent_response()

    def _trigger_agent_response(self):
        """Initiates the agent's thinking process in a background thread."""
        if self.is_thinking or self._is_terminating:
            return

        self.is_thinking = True

        if start_pipeline(self._process_message_thread()) is False:
            self.is_thinking = False
            if not self.force_stop and not self.message_queue.empty() and self._pipeline_retry_attempts < self._pipeline_retry_limit:
                self._pipeline_retry_attempts += 1
                if self._pipeline_retry_attempts == 1:
                    self._add_message(
                        "SYSTEM",
                        "<i>Previous pipeline is still winding down. Your prompt is queued and will start shortly...</i>",
                        True,
                    )
                QtCore.QTimer.singleShot(250, self._trigger_agent_response)
                return

            self._pipeline_retry_attempts = 0
            # Drain the queue instead of replacing it to ensure consistency
            while not self.message_queue.empty():
                try:
                    self.message_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

            from ainalyse.async_manager import ASYNC_SHUTTING_DOWN

            if ASYNC_SHUTTING_DOWN:
                error_msg = "AETHER is currently shutting down or in an invalid state. Please restart IDA."
            else:
                error_msg = "Another function is currently being executed. Please resend prompt after other function has completed..."

            self._add_message("AETHER", f"<i>Prompt failed: {error_msg}</i>", True)
        else:
            self._pipeline_retry_attempts = 0
            self._add_message("AETHER", "<i>Thinking...</i>", True)

    def _request_force_stop(self):
        if self._is_terminating:
            return

        self.force_stop = True
        self.stop_generation += 1
        cancel_pipeline()

        # Swap to a fresh queue so any in-flight stale worker cannot consume
        # and drop post-stop user input while it is unwinding.
        self.message_queue = asyncio.Queue()

    @use_async_worker("AetherAgent")
    async def _process_message_thread(self):
        """(Worker Thread) Drive the chatbot through the multi_agent_runtime step loop."""
        worker_stop_generation = self.stop_generation
        self._worker_loop = asyncio.get_running_loop()
        source_queue = self.message_queue
        try:
            while self.is_running and not self.force_stop and not self._is_terminating:
                if worker_stop_generation != self.stop_generation:
                    break

                packet = None
                try:
                    packet = await asyncio.wait_for(source_queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    if source_queue is not self.message_queue:
                        source_queue = self.message_queue
                    continue
                try:
                    msg_type = packet.get("type")
                    content = packet.get("content")
                    if self.force_stop or worker_stop_generation != self.stop_generation:
                        break

                    if msg_type != "user_input":
                        continue

                    user_label = self._label_user_query(bool(packet.get("is_interrupt")))
                    self.logger.info("%s: %s", user_label, content)
                    user_content = f"{user_label}: {content}"
                    self.agent_state.conversation_history.append({"role": "user", "content": user_content})

                    struct_request = self._extract_struct_delegate_request(content)
                    if struct_request is not None:
                        request_text = struct_request.get("raw") or content
                        response = await asyncio.to_thread(
                            self.chatbot_agent.specialist_orchestrator.send_struct_message,
                            message=request_text,
                            relevant_functions=list(struct_request.get("relevant_functions") or []),
                            context_description=str(struct_request.get("context_description", "")),
                        )

                        def sync_render_struct():
                            self._render_struct_delegation_response(struct_request, response)
                            return 1

                        self._safe_execute_sync(sync_render_struct, ida_kernwin.MFF_WRITE)
                        self._finalize_conversation()
                        continue

                    state = None
                    while not self.force_stop and worker_stop_generation == self.stop_generation and not self._is_terminating:
                        system_prompt = finalize_prompt(self.base_prompt) + self._build_tool_prompt()
                        executor = self._create_runtime_loop_executor(system_prompt)
                        if state is None:
                            state = self.chatbot_agent.create_loop_state(executor, "")

                        step = await asyncio.to_thread(self.chatbot_agent.step, executor, state)

                        # Special transition tool: delegate_struct_task only triggers
                        # handoff. Resolve the actual StructAgent response here.
                        for tool_result in list(step.tool_results or []):
                            if str(tool_result.get("name", "")) != ToolNames.DELEGATE_STRUCT_TASK.value:
                                continue
                            raw_result = str(tool_result.get("result", "") or "")
                            if not raw_result.startswith("[STRUCT_DELEGATED]"):
                                continue

                            def sync_render_delegate_tool_call():
                                self._render_pending_delegate_struct_tool_call(tool_result)
                                return 1

                            self._safe_execute_sync(sync_render_delegate_tool_call, ida_kernwin.MFF_WRITE)
                            request_id = raw_result[len("[STRUCT_DELEGATED]") :].strip()
                            response_text = await asyncio.to_thread(
                                self.chatbot_agent.specialist_orchestrator.wait_for_struct_response,
                                request_id,
                            )
                            tool_result["result"] = response_text

                        if self.force_stop or worker_stop_generation != self.stop_generation:
                            self.logger.info("Force stop detected. Discarding in-flight runtime step.")
                            break

                        finished = [False]

                        def sync_step():
                            finished[0] = self._handle_runtime_step(step)
                            return 1

                        self._safe_execute_sync(sync_step, ida_kernwin.MFF_WRITE)
                        if finished[0]:
                            break

                finally:
                    source_queue.task_done()
        except Exception as e:
            error_message = f"An error occurred in worker thread: {e}"
            self.logger.exception(error_message)
            import traceback

            error_traceback = traceback.format_exc()
            self.logger.error(error_traceback)
            if not self._is_terminating:

                def sync_error():
                    self._add_message("AETHER", f"<i>{html.escape(error_message)}</i>", True)
                    return 1

                self._safe_execute_sync(sync_error, ida_kernwin.MFF_WRITE)
        finally:
            self._worker_loop = None
            self.is_thinking = False
        self.logger.info("Worker thread terminated gracefully.")

    def _create_runtime_loop_executor(self, system_prompt: str):
        config = load_config()
        return self.chatbot_agent.create_loop_executor(
            system_prompt=system_prompt,
            model=config.get("OPENAI_MODEL", "gpt-4"),
            max_iterations=config.get("CHATBOT_MAX_ITERATIONS", -1),
            max_tokens=self.max_tokens,
            temperature=0.7,
            enabled_tools=self.exposed_tools,
            max_tool_calls=MAX_TOOL_CALLS,
            feature="chatbot",
            verbose_output_dir=self.verbose_output_dir,
        )

    def _build_tool_prompt(self) -> str:
        # Get what is ACTUALLY exposed to the LLM right now (honors index state)
        definitions = self.chatbot_agent.get_tool_definitions(set(self.exposed_tools))
        effective_available_tools = {d["function"]["name"] for d in definitions}

        configured_enabled_tools = set(self.exposed_tools)
        runtime_available_tools = {tool_name.value for tool_name in TOOL_REGISTRY.keys()}

        # Tools the user disabled in settings
        user_disabled_tools = runtime_available_tools - configured_enabled_tools

        # Tools the user ENABLED, but we hid at runtime because the index is missing
        runtime_locked_tools = configured_enabled_tools - effective_available_tools

        prompt_segment = "\n--- AGENT TOOL STATUS ---\n"
        # --- Available Tools Section ---
        if effective_available_tools:
            available_list = "\n".join([f"* {name}" for name in sorted(list(effective_available_tools))])
            prompt_segment += (
                "**AVAILABLE TOOLS:** The following IDA/AETHER functions are currently enabled "
                "and available at runtime. The Agent may call them to gather data "
                "or perform actions:\n"
                f"{available_list}\n"
            )
        else:
            prompt_segment += (
                "**AVAILABLE TOOLS:** None. The Agent cannot perform any external actions or gather binary data beyond its core knowledge.\n"
            )

        prompt_segment += "\n"

        # --- Unavailable Tools Section ---
        if user_disabled_tools:
            unavailable_list = "\n".join([f"* {name}" for name in sorted(list(user_disabled_tools))])
            prompt_segment += (
                "**UNAVAILABLE TOOLS (USER SETTINGS):** The following tools exist but have been disabled "
                "by the user. They cannot be called:\n"
                f"{unavailable_list}\n"
            )

        if runtime_locked_tools:
            runtime_locked_list = "\n".join([f"* {name}" for name in sorted(list(runtime_locked_tools))])
            prompt_segment += (
                "\n**UNAVAILABLE TOOLS (RUNTIME LOCK):** The following user-enabled tools are temporarily "
                "unavailable due to runtime state (for example, index lockout). They cannot be called right now:\n"
                f"{runtime_locked_list}\n"
            )

        # --- Instructions/Note ---
        prompt_segment += (
            "\n**NOTE:** Use native tool calling for any enabled tool use. Do not emit fenced-code tool syntax or XML tags (like <tool_call>). "
            "If an action requires an unavailable tool, please inform the user "
            "that the tool is restricted and request permission to enable it via the Chatbot Settings.\n"
        )

        prompt_segment += "-------------------------\n"

        return prompt_segment

    def _label_user_query(self, is_interrupt: bool = False) -> str:
        if is_interrupt:
            return "[**USER INTERRUPT/OVERRIDE**]"
        if self.agent_state.conversation_history:
            return "FOLLOW-UP USER QUERY"
        return "USER QUERY"

    def _extract_struct_delegate_request(self, content: str) -> dict | None:
        text = (content or "").strip()
        if not text.lower().startswith("/struct"):
            return None

        body = text[len("/struct") :].strip()
        if not body:
            return {
                "suggested_struct_name": "unknown_struct",
                "relevant_functions": [],
                "context_description": "",
                "metadata": {},
            }

        parts = [part.strip() for part in body.split("|")]
        struct_name = parts[0] if parts and parts[0] else "unknown_struct"
        functions = []
        if len(parts) > 1 and parts[1]:
            functions = [value.strip() for value in re.split(r"[,\s]+", parts[1]) if value.strip()]
        context_description = parts[2] if len(parts) > 2 else ""
        metadata = {"source": "ui_struct_delegate", "raw": text}
        return {
            "suggested_struct_name": struct_name,
            "relevant_functions": functions,
            "context_description": context_description,
            "metadata": metadata,
        }

    def _render_struct_delegation_response(self, request: dict, response_text: str) -> None:
        self._add_message("SYSTEM", "<b>Delegating to StructAgent...</b>", True)
        self._add_message(
            "SYSTEM",
            html.escape(f"Struct request: name={request.get('suggested_struct_name')} functions={request.get('relevant_functions', [])}"),
            True,
        )
        self._add_message("SYSTEM", html.escape(str(response_text or "StructAgent returned no response.")), True)
        self._emit_specialist_updates()

    def _set_active_agent(self, agent_name: str) -> None:
        next_agent = str(agent_name or "AETHER").strip() or "AETHER"
        if self.active_agent == next_agent:
            return
        self.active_agent = next_agent
        self.logger.info("Active agent switched to %s", self.active_agent)
        self._add_message("SYSTEM", html.escape(f"[Active agent: {self.active_agent}]"), True)

    def _emit_struct_agent_trace(self) -> None:
        transcript = list(self.agent_state.context.pop("last_struct_agent_transcript", []) or [])
        if not transcript:
            self.logger.info("StructAgent trace unavailable for current turn")
            return
        formatted = "\n".join(f"- {line}" for line in transcript)
        self.logger.info("Rendering StructAgent trace lines=%s", len(transcript))
        self._add_message("SYSTEM", html.escape("StructAgent trace available."), True)
        self._add_message("STRUCT_AGENT", html.escape(f"StructAgent trace:\n{formatted}"), True)

    def _emit_specialist_updates(self) -> None:
        updates = list(self.agent_state.context.pop("specialist_updates", []) or [])
        if not updates:
            return
        self.logger.info("Rendering specialist updates count=%s", len(updates))
        for update in updates:
            agent_id = str(update.get("agent_id", "") or "specialist").upper()
            self._set_active_agent(agent_id)
            message_text = str(update.get("response_text", "") or "").strip()
            rendered_tool_calls = []
            transcript = list(update.get("transcript", []) or [])
            if transcript:
                for line in transcript:
                    entry = str(line or "").strip()
                    if not entry:
                        continue
                    if entry.startswith("request:"):
                        self._add_message("SYSTEM", html.escape(f"[{self.active_agent} request]"), True)
                        self._add_message(self.active_agent, html.escape(entry[len("request:") :].strip()), True)
                        continue
                    if entry.startswith("tool:"):
                        tool_payload = entry[len("tool:") :].strip()
                        tool_name = ""
                        args_text = "{}"
                        status = "OK"

                        if " args=" in tool_payload:
                            tool_name, rest = tool_payload.split(" args=", 1)
                            tool_name = tool_name.strip()
                            if " result=" in rest:
                                args_text, result_text = rest.split(" result=", 1)
                                args_text = args_text.strip()
                                status = self._tool_call_status(result_text)
                            else:
                                args_text = rest.strip()
                        else:
                            tool_name = tool_payload

                        rendered_output = {
                            "name": tool_name,
                            "args": args_text,
                            "status": status,
                        }
                        rendered_tool_calls.append(rendered_output)
                        continue
                    if entry.startswith("reply:"):
                        self._add_message(self.active_agent, html.escape(entry[len("reply:") :].strip()), True)
                        continue
                    if entry.startswith("assistant:"):
                        self._add_message(self.active_agent, html.escape(entry[len("assistant:") :].strip()), True)
                        continue
                    if entry.startswith("warning:") or entry.startswith("error:"):
                        self._add_message("SYSTEM", html.escape(entry), True)
                        continue
                    # Skip raw request lines in UI to match main agent style.
                    if entry.startswith("request:"):
                        continue
                    self._add_message(self.active_agent, html.escape(entry), True)

            if message_text:
                self._add_message("SYSTEM", html.escape(f"[{self.active_agent} final response]"), True)
                self._add_message(self.active_agent, html.escape(message_text), True)
            if rendered_tool_calls:
                self._add_message("SYSTEM", "<b>Executing Tools...</b>", True)
                rendered_ui_output = "## Tool Calls:\n" + "\n".join(
                    f"{item['name']} | args={item['args']} | status={item['status']}" for item in rendered_tool_calls
                )
                self._add_message("SYSTEM", html.escape(rendered_ui_output), True)
        # Keep specialist as active while it is still running; only switch back
        # when orchestrator clears active_specialist_agent.
        active_specialist = str(self.agent_state.context.get("active_specialist_agent", "") or "").strip()
        if not active_specialist:
            self._set_active_agent("AETHER")

    def _notify_specialist_progress(self) -> None:
        if self._is_terminating:
            return

        def sync_emit_progress():
            self._emit_specialist_updates()
            return 1

        try:
            self._safe_execute_sync(sync_emit_progress, ida_kernwin.MFF_WRITE)
        except Exception:
            self.logger.debug("Failed to render live specialist progress", exc_info=True)

    def _handle_runtime_step(self, step) -> bool:
        """Render one multi_agent_runtime step and decide whether the chat turn is complete."""
        if self.force_stop or self._is_terminating:
            return True

        assistant_message = step.assistant_message or {}
        response_text = str(assistant_message.get("content", "") or "")
        if response_text:
            self.logger.info("Assistant response: %s", response_text)
            # Runtime-step assistant text is always produced by the main agent.
            # Do not reuse specialist label even if specialist updates were just rendered.
            self._add_message("AETHER", response_text)

        tool_results = list(step.tool_results or [])
        if tool_results:
            if not self._pending_delegate_tool_rendered:
                self._add_message("SYSTEM", "<b>Executing Tools...</b>", True)
            rendered_messages = []
            struct_agent_messages = []
            for result in tool_results:
                tool_name = str(result.get("name", ""))
                arguments = result.get("arguments", {})
                tool_result_text = str(result.get("result", ""))
                status = self._tool_call_status(tool_result_text)

                log_msg = [f"[TOOL_CALL]{tool_name}", f"args: {self._format_tool_call_args(arguments)}", f"status: {status}"]
                if status != "OK":
                    log_msg.append(f"result: {tool_result_text}")

                rendered_output = "\n".join(log_msg)
                self.logger.info("Tool result: %s", rendered_output)
                rendered_messages.append(
                    {
                        "name": tool_name,
                        "args": self._format_tool_call_args(arguments),
                        "status": status,
                    }
                )
                if tool_name == ToolNames.DELEGATE_STRUCT_TASK.value:
                    struct_agent_messages.append(tool_result_text.strip() or "StructAgent returned an empty response.")

            if rendered_messages:
                rendered_ui_output = "## Tool Calls:\n" + "\n".join(
                    f"{message['name']} | args={message['args']} | status={message['status']}" for message in rendered_messages
                )
                self._add_message("SYSTEM", html.escape(rendered_ui_output), True)

            for message_text in struct_agent_messages:
                self.logger.info("Rendering STRUCT_AGENT message len=%s", len(message_text))
                self._add_message("SYSTEM", html.escape("[delegate_struct_task completed]"), True)
                # Final StructAgent response is rendered via _emit_specialist_updates().
                # Avoid duplicating it here in delegate tool output.

            self._emit_specialist_updates()
            self._pending_delegate_tool_rendered = False

        if step.done:
            self._finalize_conversation()
            return True
        return False

    def _render_pending_delegate_struct_tool_call(self, tool_result: dict) -> None:
        tool_name = str(tool_result.get("name", ""))
        if tool_name != ToolNames.DELEGATE_STRUCT_TASK.value:
            return
        arguments = tool_result.get("arguments", {})
        rendered_ui_output = f"## Tool Calls:\n{tool_name} | args={self._format_tool_call_args(arguments)} | status=RUNNING"
        self._add_message("SYSTEM", "<b>Executing Tools...</b>", True)
        self._add_message("SYSTEM", html.escape(rendered_ui_output), True)
        self._pending_delegate_tool_rendered = True

    @staticmethod
    def _format_tool_call_args(arguments) -> str:
        if isinstance(arguments, str):
            return arguments
        try:
            return json.dumps(arguments, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(arguments)

    @staticmethod
    def _tool_call_status(result: str) -> str:
        normalized = result.strip()
        lowered = normalized.lower()
        if normalized.startswith("[SYSTEM_ERROR]") or lowered.startswith("error"):
            return "ERROR"
        if "not found" in lowered or "failed" in lowered:
            return "FAILED"
        return "OK"

    def _finalize_conversation(self):
        """
        Mark the current turn complete while preserving chat context for follow-up queries.
        """
        if self._is_terminating:
            self.is_thinking = False
            return

        self.logger.info("Finalizing conversation and preserving state for follow-up queries...")
        self.is_running = False
        self.stop_generation += 1
        self._pipeline_retry_attempts = 0
        self.active_agent = "AETHER"
        self._add_message_threadsafe("SYSTEM", "Complete")
        self.is_thinking = False
        self.logger.info("Finalization complete.")

    def shutdown(self):
        """Stop worker activity and block new scheduling during widget/plugin teardown."""
        if self._is_terminating:
            return

        self._is_terminating = True
        self.is_running = False
        self.force_stop = True
        self.stop_generation += 1
        self._pipeline_retry_attempts = 0
        self.is_thinking = False
        cancel_pipeline()
        self.message_queue = None

    def detach_ui(self):
        """Release UI references to avoid touching Qt widgets after teardown."""
        self.parent = None
        self.main_widget = None
        self.history_view = None
        self.input_box = None
        self.context_frame = None
        self.context_gear_btn = None
        self.pills_scroll = None
        self.pills_container = None
        self.pills_layout = None
        self.search_bar = None

    def _cleanup(self):
        if self.agent_state.plan_manager.all_plans:
            try:
                self.agent_state.plan_manager.clear()
                self.logger.info("All remaining action plans cleared.")
            except Exception as e:
                self.logger.exception("Error clearing action plans: %s", e)
        self.agent_state.conversation_history.clear()
        self.active_agent = "AETHER"

    def _select_exposed_tools(self):
        SelectExposedTools.select_exposed_tools(self)
        return 1

    def _select_binary_functions_context(self):
        SelectBinaryFunctionsContext.select_binary_functions_context(self)
        return 1

    def _settle_manual_context(self) -> str:
        return SelectBinaryFunctionsContext.settle_manual_context(self)

    def _stop_currrent_prompt(self):
        StopCurrentPrompt.stop_current_prompt(self)

    def _refresh(self):
        ClearChatHistory.clear_chat_history(self)

    def _hide_search(self):
        SearchText.hide_search(self)

    def _show_search(self):
        SearchText.show_search(self)

    def _do_search(self, text, forward=True, is_next_call=False):
        SearchText.do_search(self, text, forward=forward, is_next_call=is_next_call)
