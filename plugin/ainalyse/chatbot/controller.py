import asyncio
import html
import os
import queue
import time
import traceback
from typing import Optional

import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets

from .backend.core import AgentState, TaskStatus
from .backend.parser import parse_tool_calls
from .backend.toolconfig import TOOL_CONFIG
from .backend.tools import TOOL_REGISTRY, ToolNames
from .backend.summarizer import summarize_conversation
from .. import load_config
from ..ssl_helper import create_openai_client_with_custom_ca
from ainalyse.async_manager import schedule_ui_task, start_pipeline, use_async_worker

from .context_menu_controller import SelectExposedTools, SelectBinaryFunctionsContext, StopCurrentPrompt, ClearChatHistory, SearchText

config = load_config()

BASE_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "base_chat.txt")
CONVO_LIMIT = 10
MAX_CONTEXT_FUNCTIONS = 50
MAX_TOOL_CALLS = 10
RESPONSE_BUFFER = 4000  # Reduced from 8000 to give more space for tool outputs
CONVO_BUFFER = 2000 * CONVO_LIMIT  # Reduced from 3000*10 (30KB) to 20KB for better balance
MAX_TOKENS = config.get("CHATBOT_MAX_TOKENS", 128000)  # Increased from 65536 to 128000 for chatbot tool calls


class ChatbotController:
    def __init__(self):
        self.PERSISTENT_AGENT_STATE = AgentState()
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
        self.agent_state = self.PERSISTENT_AGENT_STATE
        self.is_thinking = False
        self.force_stop = False
        self.stop_generation = 0

        # UI/main thread producers and async worker consumers run on different
        # threads. queue.Queue is thread-safe for this cross-thread handoff.
        self.message_queue = queue.Queue()
        self.is_running = True
        self.exposed_tools = {name for name, is_enabled in TOOL_CONFIG.items() if is_enabled}
        self.max_tokens = MAX_TOKENS
        self.max_cumulative_tool_output = self.max_tokens - len(self.base_prompt) - RESPONSE_BUFFER - CONVO_BUFFER
        print(f"[AETHER Chatbot] Initialized with max_tokens={self.max_tokens}, base_prompt_len={len(self.base_prompt)}, max_cumulative_tool_output={self.max_cumulative_tool_output}")

        self.theme_filter = None
        self._theme_refresh_pending = False
        self._is_applying_theme = False

        self.manual_context = []
        self.current_match_idx = 0
        self.total_matches = 0

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
            with open(BASE_PROMPT_PATH, "r", encoding="utf-8") as f:
                f_string_code = 'f"""' + f.read() + '"""'
                safe_globals = {
                    'ToolNames': ToolNames,
                    'TaskStatus': TaskStatus,
                }
                return eval(f_string_code, safe_globals, {})
        except Exception as e:
            print(f"[AETHER Chatbot] Error loading base prompt: {e}")
            return "You are a helpful reverse engineering assistant."

    # def _on_context_gear_clicked(self):
    #     self._select_binary_functions_context()

    # for themes
    # refactor into new file
    def _apply_theme_styles(self):
        """Apply theme-aware styles based on the active Qt palette."""
        if not self.main_widget:
            return
        self._is_applying_theme = True
        palette = self.main_widget.palette()

        window_color = palette.color(QtGui.QPalette.Window).name()
        button_color = palette.color(QtGui.QPalette.Button).name()
        base_color = palette.color(QtGui.QPalette.Base).name()
        text_color = palette.color(QtGui.QPalette.Text).name()
        mid_color = palette.color(QtGui.QPalette.Mid).name()

        # Detect dark mode and compute smart hover color
        text_qcolor = palette.color(QtGui.QPalette.Text)
        button_qcolor = palette.color(QtGui.QPalette.Button)
        is_dark_mode = text_qcolor.lightness() > 128
        
        if is_dark_mode:
            # Dark mode: brighten button on hover
            hover_bg_qcolor = button_qcolor.lighter(120)
        else:
            # Light mode: darken button on hover
            hover_bg_qcolor = button_qcolor.darker(120)
        
        hover_bg_color = hover_bg_qcolor.name()

        try:
            self.context_frame.setStyleSheet(f"""
                QFrame {{
                    background: {button_color};
                    border: 1px solid {mid_color};
                    border-radius: 8px;
                    padding: 4px 8px;
                }}
            """)

            self.context_gear_btn.setStyleSheet(f"""
                QPushButton {{
                    font-size: 16pt;
                    font-weight: bold;
                    color: {text_color};
                    border: 1px solid {mid_color};
                    padding: -2px 0px 2px 0px;
                    margin: 0px;
                    background: transparent;
                    border-radius: 4px;
                    height: 28px;
                    width: 28px;
                    min-height: 28px;
                    min-width: 28px;
                    line-height: 28px;
                    text-align: center;
                }}
                QPushButton:hover {{
                    color: {text_color};
                    background-color: {hover_bg_color};
                    border-radius: 4px;
                }}
            """)

            self.pills_scroll.setStyleSheet("background: transparent;")
            self.pills_scroll.verticalScrollBar().setStyleSheet(f"""
                QScrollBar:vertical {{
                    border: none;
                    background: {base_color};
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
                    background: {hover_bg_color};
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                    background: none;
                }}
                QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                    background: none;
                }}
            """)

            if self.search_bar is not None:
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
        return f'''
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
        '''

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
        from .ui.viewer import ThemeRefreshEventFilter
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
        if not self.main_widget or self._is_applying_theme:
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
            pill = QtWidgets.QPushButton(str(func['name']))
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
        cursor = self.history_view.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.history_view.setTextCursor(cursor)

    def _render_message(self, sender, message, is_html=False):
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
        self.PERSISTENT_MESSAGE_LOG.append({"sender": sender, "msg": message})
        self._render_message(sender, message, is_html)

    def send_message(self):
        user_message = self.input_box.toPlainText().strip()
        if not user_message:
            return

        self._add_message("You", user_message)
        self.input_box.clear()
        self.force_stop = False
        self.is_running = True
        self.message_queue.put_nowait({
            "type": "user_input",
            "content": self._settle_manual_context() + user_message
        })
        self.manual_context.clear()
        self._refresh_context_pills()
        if not self.is_thinking:
            self._trigger_agent_response()

    def _trigger_agent_response(self):
        """Initiates the agent's thinking process in a background thread."""
        if self.is_thinking:
            return    

        self.is_thinking = True
        self._add_message("AETHER", "<i>Thinking...</i>", True)
        
        start_pipeline(self._process_message_thread())

    def _flush_message_queue(self):
        while True:
            try:
                self.message_queue.get_nowait()
                self.message_queue.task_done()
            except queue.Empty:
                break

    def _request_force_stop(self):
        self.force_stop = True
        self.stop_generation += 1
        self._flush_message_queue()

    @use_async_worker("AetherAgent")
    async def _process_message_thread(self):
        """(Worker Thread) The main loop that processes the queue and tool outputs."""
        worker_stop_generation = self.stop_generation
        while self.is_running and not self.force_stop:
            if worker_stop_generation != self.stop_generation:
                break
            # Blocking queue read is pushed to a helper thread so the asyncio
            # worker loop stays responsive and cancellation-friendly.
            packet = await asyncio.to_thread(self.message_queue.get)
            msg_type = packet.get("type")
            content = packet.get("content")
            try:
                if self.force_stop or worker_stop_generation != self.stop_generation:
                    break

                # 2. Construct the prompt
                system_prompt = self.base_prompt + self._build_tool_prompt()
                if msg_type == "user_input":
                    if len(self.agent_state.conversation_history) <= 1:
                        user_label = "USER QUERY"
                    else:
                        user_label = "[**USER INTERRUPT/OVERRIDE**]"
                    print(f"{user_label}: {content}")
                    user_content = (
                        "--- AGENT STATE START ---\n"
                        f"{str(self.agent_state)}\n"
                        "--- AGENT STATE END ---\n\n"
                        f"{user_label}: {content}" 
                    )
                    self.agent_state.conversation_history.append({"role": "user", "content": user_content})
                elif msg_type == "tool_output":
                    self.agent_state.conversation_history.append({"role": "user", "content": content})

                messages = [{"role": "system", "content": system_prompt}] + self.agent_state.conversation_history # FOR MASKED MANUAL CONTEXT INJECTION
                
                # Check if we have anything to send to the LLM
                if len(messages) <= 1 and not content:
                    break

                # 3. Load config and make LLM call
                response_text = await asyncio.to_thread(self._llm_call, messages)

                if self.force_stop or worker_stop_generation != self.stop_generation:
                    print("[AETHER Chatbot] Force stop detected. Discarding in-flight LLM response.")
                    break

                # Parse tool calls on the worker thread first so we only block
                # the IDA main thread when UI/tool execution is required.
                tool_calls, parse_error = self._parse_tool_calls_worker(response_text)

                if self.force_stop or worker_stop_generation != self.stop_generation:
                    print("[AETHER Chatbot] Force stop detected before UI sync. Dropping response.")
                    break

                # 4. Schedule the UI update/tool execution on the main thread
                finished = [False]
                def sync_step():
                    # This captures the return value from _handle_llm_response.
                    finished[0] = self._handle_llm_response(
                        response_text,
                        tool_calls=tool_calls,
                        parse_error=parse_error,
                    )

                ida_kernwin.execute_sync(sync_step, ida_kernwin.MFF_WRITE)

                if finished[0]:
                    break

                # 5. Summarize conversation if it's too long AND the agent is still active.
                if len(self.agent_state.conversation_history) > (CONVO_LIMIT) and self.agent_state.action_plans:
                    summary_result = await summarize_conversation(self.agent_state, False)
                    print(f"[AETHER Chatbot] Mid-conversation summary triggered: {summary_result}")

            except Exception as e:
                error_message = f"An error occurred in worker thread: {e}"
                print(f"[AETHER Chatbot] {error_message}")
                import traceback
                error_traceback = traceback.format_exc()
                print(error_traceback)
                ida_kernwin.execute_sync(
                    lambda: self._handle_llm_response(
                        f"<i>{error_message}</i>",
                        tool_calls=None,
                        parse_error=None,
                    ),
                    ida_kernwin.MFF_WRITE
                )
                break # Exit loop on critical error
            finally:
                self.message_queue.task_done()
        print("[AETHER Chatbot] Worker thread terminated gracefully.")

    def _llm_call(self, messages):
        config = load_config()
        feature = "chatbot"
        client = create_openai_client_with_custom_ca(
            config["OPENAI_API_KEY"],
            config["OPENAI_BASE_URL"],
            config.get("CUSTOM_CA_CERT_PATH", ""),
            config.get("CLIENT_CERT_PATH", ""),
            config.get("CLIENT_KEY_PATH", ""),
            feature
        )
        
        response = client.chat.completions.create(
            model=config.get("OPENAI_MODEL", "gpt-4"),
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=0.7
        )
        response_text = response.choices[0].message.content.strip()
        return response_text

    def _parse_tool_calls_worker(self, response_text: str):
        """
        Parse tool calls on the async worker thread before execute_sync.

        This keeps parsing/string-processing work off IDA's main thread,
        reducing perceived UI lag before tool execution begins.

        Args:
            response_text: Raw assistant response text.

        Returns:
            Tuple: (tool_calls, parse_error)
                tool_calls: Parsed tool call list (or empty list).
                parse_error: Error string on parse failure, else None.
        """
        try:
            tool_calls = parse_tool_calls(response_text)
            return tool_calls, None
        except Exception as e:
            return [], str(e)
    
    def _build_tool_prompt(self) -> str:
        all_tool_names = {tool_name.value for tool_name in TOOL_REGISTRY.keys()}
        enabled_tools = self.exposed_tools
        unavailable_tools = all_tool_names - enabled_tools

        prompt_segment = "\n--- AGENT TOOL STATUS ---\n"
        # --- Available Tools Section ---
        if enabled_tools:
            available_list = "\n".join([f"* {name}" for name in sorted(list(enabled_tools))])
            prompt_segment += (
                "**AVAILABLE TOOLS:** The following IDA/AETHER functions are currently enabled "
                "for your use by the user's configuration. The Agent may call them to gather data "
                "or perform actions:\n"
                f"{available_list}\n"
            )
        else:
            prompt_segment += (
                "**AVAILABLE TOOLS:** None. The Agent cannot perform any external actions "
                "or gather binary data beyond its core knowledge.\n"
            )
            
        prompt_segment += "\n"
        
        # --- Unavailable Tools Section ---
        if unavailable_tools:
            unavailable_list = "\n".join([f"* {name}" for name in sorted(list(unavailable_tools))])
            prompt_segment += (
                "**UNAVAILABLE TOOLS:** The following tools exist but have been disabled "
                "by the user. They cannot be called:\n"
                f"{unavailable_list}\n"
            )
            
        # --- Instructions/Note ---
        prompt_segment += (
            "\n**NOTE:** If an action requires an unavailable tool, please inform the user "
            "that the tool is restricted and request permission to enable it via the Chatbot Settings.\n"
        )
        
        prompt_segment += "-------------------------\n"

        return prompt_segment
    
    def _handle_llm_response(
        self,
        response_text: str,
        tool_calls=None,
        parse_error: Optional[str] = None,
    ):
        """
        (Main Thread) Update UI, execute parsed tools, and advance the loop.

        Notes:
            Tool-call parsing is intentionally done on the worker thread in
            `_parse_tool_calls_worker` before this function is called via
            `ida_kernwin.execute_sync`, so the main thread is blocked for less
            time.

        Args:
            response_text: Assistant response text.
            tool_calls: Pre-parsed tool call list. If None, this function treats
                it as no tool calls.
            parse_error: Parse error captured by worker thread, if any.
        """
        """
        # Remove the "Thinking..." message
        self.is_thinking = False
        cursor = self.history_view.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.select(QtGui.QTextCursor.BlockUnderCursor)
        cursor.removeSelectedText()
        cursor.deletePreviousChar() # Clean up newline
        self.history_view.setTextCursor(cursor)
        """
        if self.force_stop:
            return True
        print(response_text)
        # Add AI response to UI and memory
        self._add_message("AETHER", response_text)
        # self.agent_state.add_short_term_memory(key=f"aether_response_{len(self.agent_state.short_term_mem)}", value=response_text)
        self.agent_state.conversation_history.append({"role": "assistant", "content": response_text})
        should_terminate = False

        # Execute pre-parsed tool calls on the main thread.
        if parse_error:
            self._add_message("SYSTEM", f"<i>Error parsing tool calls: {html.escape(parse_error)}</i>", True)
            should_terminate = True
        else:
            parsed_tool_calls = tool_calls or []
            if parsed_tool_calls:
                self._add_message("SYSTEM", "<b>Executing Tools...</b>", True)
                tool_outputs = []
                executed_count = 0
                cumulative_len = 0
                for call in parsed_tool_calls:
                    tool_name = call.get("tool_name")
                    args = call.get("args", [])
                    
                    if should_terminate:
                        tool_outputs.append(f"Skipped tool '{tool_name}': Termination sequence initiated by a previous tool.")
                        continue

                    if executed_count >= MAX_TOOL_CALLS or cumulative_len >= self.max_cumulative_tool_output:
                        reason = "COUNT_LIMIT" if executed_count >= MAX_TOOL_CALLS else "LENGTH_LIMIT"
                        # Dense error message for LLM consumption
                        fail_notice = f"[SYSTEM_ERROR] Tool '{tool_name}' with args: ({args}) is BLOCKED. Reason: {reason} ({cumulative_len}/{self.max_cumulative_tool_output} chars). Retry with less tool calls."
                        print(f"[AETHER Chatbot] Tool blocked - {reason}: executed={executed_count}/{MAX_TOOL_CALLS}, cumulative_len={cumulative_len}/{self.max_cumulative_tool_output}")
                        tool_outputs.append(fail_notice)
                        continue

                    if tool_name in TOOL_REGISTRY:
                        tool_func = TOOL_REGISTRY[tool_name]
                        try:
                            # Note: All tool functions must accept 'state' as the first argument
                            tool_output = tool_func(self.agent_state, *args)
                            if not should_terminate:
                                pre= f'''[OUTPUT_START]{tool_name}
'''
                                tool_output = pre + tool_output + '\n[OUTPUT_END]'
                                print(tool_output)
                                tool_outputs.append(tool_output)
                                executed_count += 1
                                cumulative_len += len(tool_output)
                            if tool_name == ToolNames.REMOVE_ACTION_PLAN and not self.agent_state.action_plans:
                                print("[AETHER Chatbot] Final plan removed. Terminating conversation loop.")
                                should_terminate = True
                        except Exception as e:
                            error_msg = f"Error executing tool '{tool_name}' with args {args}: {e}"
                            print(f"[AETHER Chatbot] {error_msg}")
                            self._add_message("SYSTEM", f"<i>{html.escape(error_msg)}</i>", True)
                    else:
                        error_msg = f"Unknown tool: '{tool_name}'"
                        print(f"[AETHER Chatbot] {error_msg}")
                        self._add_message("SYSTEM", f"<i>{html.escape(error_msg)}</i>", True)
                
                if tool_outputs and not should_terminate:
                    combined_output = "## Tool Outputs:\n" + "\n".join(tool_outputs)
                    self.message_queue.put_nowait({
                        "type": "tool_output", 
                        "content": combined_output
                    })
            else:
                should_terminate = True

        if should_terminate:
            self._finalize_conversation()
        return should_terminate

    def _finalize_conversation(self):
        """
        Cleans up the agent state after a task is fully concluded.
        This includes summarizing the entire conversation history and clearing all action plans.
        """
        print("[AETHER Chatbot] Finalizing conversation and cleaning state...")
        # Summarize all history and get the raw summary text
        async def run_finalization():
            try:
                # 1. Perform the heavy async summarization (OpenAI call)
                summary = await summarize_conversation(self.agent_state, finalize=True)
                
                # 2. Update UI and State on IDA's Main Thread
                def update_ui_sync():
                    self._add_message("AETHER", summary)
                    self._cleanup()
                    self._add_message("SYSTEM", "Complete")
                    self.is_thinking = False
                    print("[AETHER Chatbot] Finalization complete.")

                # Bridge back to the Main Thread for UI/IDA API calls
                ida_kernwin.execute_sync(update_ui_sync, ida_kernwin.MFF_WRITE)
                
            except Exception as e:
                print(f"[AETHER Chatbot] Error during final summarization: {e}")
                # Ensure we reset the thinking flag even on failure
                ida_kernwin.execute_sync(lambda: setattr(self, 'is_thinking', False), ida_kernwin.MFF_WRITE)

        from ..async_manager import schedule_ui_task
        schedule_ui_task(run_finalization())

    def _cleanup(self):
        if self.agent_state.action_plans:
            try:
                self.agent_state.action_plans.clear()
                print("[AETHER Chatbot] All remaining action plans cleared.")
            except Exception as e:
                print(f"[AETHER Chatbot] Error clearing action plans: {e}")
        self.agent_state.conversation_history.clear()

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

    def _show_search(self) :
        SearchText.show_search(self)

    def _do_search(self, text, forward=True, is_next_call=False) :
        SearchText.do_search(self, text, forward=forward, is_next_call=is_next_call)