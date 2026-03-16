import os
import queue
import asyncio
import traceback, time
import html

import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets

from .. import load_config, validate_analysis_config
from ..ssl_helper import create_openai_client_with_custom_ca

# AETHER imports
from .core import AgentState, TaskStatus
from .parser import parse_tool_calls
from .toolconfig import TOOL_CONFIG, save_tool_config
from .tools import TOOL_REGISTRY, ToolNames
from .manual_context_selection import select_context_functions, aether_thread_function
from ainalyse.manual_gatherer import run_manual_gatherer_agent
from ainalyse.annotator import run_annotator_agent

from ainalyse.async_manager import use_async_worker, start_pipeline, run_in_background, run_async_in_ida

# --- Global Persistent State ---
PERSISTENT_AGENT_STATE = AgentState()
PERSISTENT_MESSAGE_LOG = []

config = load_config()

# --- Constants ---
CHATBOT_VIEW_TITLE = "AETHER Chatbot"
MAX_TOKENS = config.get("CHATBOT_MAX_TOKENS", 65536)
BASE_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "..", "prompts", "base_chat.txt")
CONVO_LIMIT = 10 # For summarizer
MAX_CONTEXT_FUNCTIONS = 50
MAX_TOOL_CALLS = 10
RESPONSE_BUFFER = 8000
CONVO_BUFFER = 3000 * CONVO_LIMIT

class ChatInputBox(QtWidgets.QTextEdit):
    returnPressed = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(ChatInputBox, self).__init__(parent)
        self.setPlaceholderText("Type your message here... (Shift+Enter for new line)")
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        
        # Connect text changes to the resize function
        self.textChanged.connect(self.adjust_height)
        self.document().documentLayout().documentSizeChanged.connect(self.adjust_height)
        
        # Set constraints
        self.min_height = 30
        self.max_height = 150
        self.setFixedHeight(self.min_height)

    def adjust_height(self):
        """Dynamically adjust height based on document content."""
        doc_height = int(self.document().size().height())
        margins = self.contentsMargins()
        needed_height = doc_height + margins.top() + margins.bottom() + 5
        
        if needed_height > self.max_height:
            self.setFixedHeight(self.max_height)
            self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        else:
            self.setFixedHeight(max(self.min_height, needed_height))
            self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

    def keyPressEvent(self, event):
        """Handle Enter to send, Shift+Enter to break line."""
        if event.key() == QtCore.Qt.Key_Return or event.key() == QtCore.Qt.Key_Enter:
            if event.modifiers() & QtCore.Qt.ShiftModifier:
                # Normal Shift+Enter behavior (new line)
                super(ChatInputBox, self).keyPressEvent(event)
            else:
                # Enter without Shift: Emit the send signal
                self.returnPressed.emit()
                event.accept()
        else:
            super(ChatInputBox, self).keyPressEvent(event)

class FlowLayout(QtWidgets.QLayout):
    """A custom layout that wraps items to the next line when space runs out.
    For context menu function selection
    """
    def __init__(self, parent=None, margin=0, spacing=-1):
        super(FlowLayout, self).__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self.itemList = []

    def __del__(self):
        item = self.takeAt(0)
        while item:
            item = self.takeAt(0)

    def addItem(self, item):
        self.itemList.append(item)

    def count(self):
        return len(self.itemList)

    def itemAt(self, index):
        if index >= 0 and index < len(self.itemList):
            return self.itemList[index]
        return None

    def takeAt(self, index):
        if index >= 0 and index < len(self.itemList):
            return self.itemList.pop(index)
        return None

    def expandingDirections(self):
        return QtCore.Qt.Orientations(QtCore.Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        height = self._doLayout(QtCore.QRect(0, 0, width, 0), True)
        return height

    def setGeometry(self, rect):
        super(FlowLayout, self).setGeometry(rect)
        self._doLayout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QtCore.QSize()
        for item in self.itemList:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QtCore.QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def _doLayout(self, rect, testOnly):
        x = rect.x()
        y = rect.y()
        lineHeight = 0
        spacing = self.spacing()

        for item in self.itemList:
            spaceX = spacing
            spaceY = spacing
            nextX = x + item.sizeHint().width() + spaceX
            
            # If the item hits the right edge, drop it to the next line
            if nextX - spaceX > rect.right() and lineHeight > 0:
                x = rect.x()
                y = y + lineHeight + spaceY
                nextX = x + item.sizeHint().width() + spaceX
                lineHeight = 0

            if not testOnly:
                item.setGeometry(QtCore.QRect(QtCore.QPoint(x, y), item.sizeHint()))

            x = nextX
            lineHeight = max(lineHeight, item.sizeHint().height())

        return y + lineHeight - rect.y()

class ChatbotViewer(ida_kernwin.PluginForm):
    def __init__(self, dock_target="Pseudocode-A"):
        super(ChatbotViewer, self).__init__()
        self.dock_target = dock_target
        self.parent = None
        self.history_view = None
        self.input_box = None
        self.agent_state = AgentState()
        self.base_prompt = self._load_base_prompt()
        self.is_thinking = False
        self.force_stop = False
        # Thread-safe queue for user input
        self.message_queue = asyncio.Queue()
        self.is_running = True
        self.exposed_tools = {
            name for name, is_enabled in TOOL_CONFIG.items() if is_enabled
        }
        self.max_tokens = MAX_TOKENS
        self.agent_state = PERSISTENT_AGENT_STATE
        self.manual_context = list() # required for manual context selection
        self.max_cumulative_tool_output = self.max_tokens - len(self.base_prompt) - RESPONSE_BUFFER - CONVO_BUFFER
        self.search_bar = None
        self.theme_filter = None
        self._theme_refresh_pending = False
        self._is_applying_theme = False

    def OnCreate(self, form):
        """Called when the form is created by IDA.""" 
        self.parent = self.FormToPyQtWidget(form)
        self._init_ui()

    def _load_base_prompt(self) -> str:
        """Loads the base prompt from the file system."""
        try:
            with open(BASE_PROMPT_PATH, "r", encoding="utf-8") as f:
                # return eval('f"""' + f.read() + '"""')
                f_string_code = 'f"""' + f.read() + '"""'
                safe_globals = {
                    'ToolNames': ToolNames,
                    'TaskStatus': TaskStatus
                }
                return eval(f_string_code, safe_globals, {})
                
        except Exception as e:
            print(f"[AETHER Chatbot] Error loading base prompt: {e}")
            return "You are a helpful reverse engineering assistant."

    def _init_ui(self):
        """Initializes the UI components of the chatbot."""
        # Central widget to hold everything
        self.main_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(self.main_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Create and store the filter object as an attribute
        self.esc_filter = EscapeEventFilter(self)
        self.main_widget.installEventFilter(self.esc_filter)

        # Search bar
        self.search_bar = SearchBarWidget()
        self.search_bar.setVisible(False)
        self.search_bar.next_clicked.connect(lambda text: self._do_search(text, forward=True, is_next_call=True))
        self.search_bar.prev_clicked.connect(lambda text: self._do_search(text, forward=False, is_next_call=True))
        self.search_bar.close_clicked.connect(self._hide_search)
        self.search_bar.search_input.textChanged.connect(self._do_search)

        layout.addWidget(self.search_bar)

        # Tracking for X/Y for searchbar
        self.current_match_idx = 0
        self.total_matches = 0

        # History View
        self.history_view = QtWidgets.QTextEdit()
        self.history_view.setReadOnly(True)
        self.history_view.document().setDocumentMargin(10)
        # Enable HTML interaction for links or formatted code
        self.history_view.setAcceptRichText(True) 
        self.history_view.setPlaceholderText("Welcome to the AETHER Chatbot...")
        self.history_view.setStyleSheet("font-size: 10pt;")
        
        # Context Menu
        self.history_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.history_view.customContextMenuRequested.connect(self._show_context_menu)
        self.history_view.installEventFilter(self.esc_filter)

        layout.addWidget(self.history_view)

        self.context_frame = QtWidgets.QFrame()
        self.context_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.context_frame.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        context_hbox = QtWidgets.QHBoxLayout(self.context_frame)
        context_hbox.setContentsMargins(4, 2, 4, 2)
        context_hbox.setSpacing(6)

        # Context button - add binary functions as context
        self.context_gear_btn = QtWidgets.QPushButton()
        self.context_gear_btn.setFixedSize(28, 28)
        self.context_gear_btn.setCursor(QtCore.Qt.PointingHandCursor)
        
        # Try gear icon for Linux first, then fallback to plus emoji
        icon = QtGui.QIcon.fromTheme("preferences-system")
        if icon.isNull():
            icon = QtGui.QIcon.fromTheme("preferences-desktop")
        
        if icon.isNull():
            self.context_gear_btn.setText("+")
            self.context_gear_btn.setStyleSheet("""
                QPushButton {
                    font-size: 16pt;
                    font-weight: bold;
                    border: none;
                    padding: -2px 0px 2px 0px;
                    margin: 0px;
                    height: 28px;
                    width: 28px;
                    min-height: 28px;
                    min-width: 28px;
                    line-height: 28px;
                    text-align: center;
                }
            """)
        else:
            self.context_gear_btn.setIcon(icon)
        self.context_gear_btn.setToolTip("Add context from binary functions")
        self.context_gear_btn.clicked.connect(self._on_context_gear_clicked)
        context_hbox.addWidget(self.context_gear_btn)

        # Pills container (Vertical Scroll)
        self.pills_scroll = QtWidgets.QScrollArea()
        self.pills_scroll.setWidgetResizable(True)
        
        # Turn OFF horizontal, turn ON vertical
        self.pills_scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.pills_scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        
        self.pills_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.pills_scroll.setStyleSheet("background: transparent;")
        
        # Lock the height. 45px shows 1 row, 75px shows 2 rows before scrolling.
        # Adjust based on how much space you want to give the pills by default.
        self.pills_scroll.setFixedHeight(45) 
        
        self.pills_container = QtWidgets.QWidget()
        self.pills_container.setStyleSheet("background: transparent;")

        # Use the custom FlowLayout
        self.pills_layout = FlowLayout(self.pills_container, margin=0, spacing=6)
        
        self.pills_scroll.setWidget(self.pills_container)
        context_hbox.addWidget(self.pills_scroll)

        layout.addWidget(self.context_frame)

        # Input Box
        self.input_box = ChatInputBox()
        self.input_box.returnPressed.connect(self.send_message)
        self.input_box.installEventFilter(self.esc_filter)
        layout.addWidget(self.input_box)

        self._apply_theme_styles()
        self._install_theme_refresh_hook()

        self._refresh_context_pills()

        # Attach to IDA's parent form
        # Secondary layout or direct parenting
        main_layout = QtWidgets.QVBoxLayout(self.parent)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.main_widget)
        
        for entry in PERSISTENT_MESSAGE_LOG:
            self._render_message(entry['sender'], entry['msg'])

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

    def _on_context_gear_clicked(self):
        self._select_binary_functions_context()

    def _refresh_context_pills(self):
        palette = self.main_widget.palette()
        pill_style = self._build_pill_stylesheet(palette)

        # Remove all old pills
        for i in reversed(range(self.pills_layout.count())):
            widget = self.pills_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        # Safety Check if list is massive do not add
        if len(self.manual_context) > MAX_CONTEXT_FUNCTIONS:
            warning_label = QtWidgets.QLabel(f"!! Too many functions selected ({len(self.manual_context)}). Unable to display.")
            warning_label.setStyleSheet("color: red; font-weight: bold;")
            self.pills_layout.addWidget(warning_label)
            return
        # Add a pill for each item in manual_context
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

    def _show_context_menu(self, position):
        menu = QtWidgets.QMenu(self.parent)
        standard_menu = self.history_view.createStandardContextMenu()
        for action in standard_menu.actions():
            action.setParent(menu) 
            menu.addAction(action)
        
        menu.addSeparator()

        # Custom Actions for Chatbot
        ## Find
        ## Clear short term memory
        ## Manually Select Available Functions
        ## Stop
        menu.addAction("Find (Ctrl+F)", self._show_search)
        menu.addAction("Clear Chat History", self._refresh)
        menu.addAction("Manually Select Available Functions", self._select_exposed_tools)
        # menu.addAction("Manually Select Binary Functions as Context", self._select_binary_functions_context)
        menu.addAction("Stop Prompt", self._stop_currrent_prompt)
        

        global_pos = self.history_view.viewport().mapToGlobal(position)
        menu.exec_(global_pos)

    def send_message(self):
        """Handles sending a message from the input box."""            
        user_message = self.input_box.toPlainText().strip()
        if not user_message:
            return

        self._add_message("You", user_message)
        self.input_box.clear()

        self.force_stop = False
        self.is_running = True
        self.message_queue.put_nowait({
            "type": "user_input", 
            "content": self.settle_manual_context() + user_message
        })
        self.manual_context.clear()
        self._refresh_context_pills()
        if not self.is_thinking:
            self._trigger_agent_response()

    def _trigger_agent_response(self):
        """Initiates the agent's thinking process in a background thread."""
        if self.is_thinking:
            return    
        
        self._add_message("AETHER", "<i>Thinking...</i>", True)
        
        start_pipeline(self._process_message_thread())

    @use_async_worker(name="AetherAgent")
    async def _process_message_thread(self):
        """(Worker Thread) The main loop that processes the queue and tool outputs."""
        while self.is_running and not self.force_stop:
            packet = await self.message_queue.get()
            msg_type = packet.get("type")
            content = packet.get("content")
            try:
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

                # 4. Schedule the UI update/tool execution on the main thread
                finished = [False]
                def sync_step():
                    # This captures the 'return should_terminate' from above
                    finished[0] = self._handle_llm_response(response_text)

                ida_kernwin.execute_sync(sync_step, ida_kernwin.MFF_WRITE)

                if finished[0]:
                    break

                # 5. Summarize conversation if it's too long AND the agent is still active.
                if len(self.agent_state.conversation_history) > (CONVO_LIMIT) and self.agent_state.action_plans:
                    from .summarizer import summarize_conversation
                    summary_result = await summarize_conversation(self.agent_state, False)
                    print(f"[AETHER Chatbot] Mid-conversation summary triggered: {summary_result}")

            except Exception as e:
                error_message = f"An error occurred in worker thread: {e}"
                print(f"[AETHER Chatbot] {error_message}")
                import traceback
                error_traceback = traceback.format_exc()
                print(error_traceback)
                ida_kernwin.execute_sync(
                    lambda: self._handle_llm_response(f"<i>{error_message}</i>"),
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

    def _handle_llm_response(self, response_text: str):
        """(Main Thread) Updates the UI, executes tools, and triggers the next agent cycle."""
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
            return
        print(response_text)
        # Add AI response to UI and memory
        self._add_message("AETHER", response_text)
        # self.agent_state.add_short_term_memory(key=f"aether_response_{len(self.agent_state.short_term_mem)}", value=response_text)
        self.agent_state.conversation_history.append({"role": "assistant", "content": response_text})
        should_terminate = False
        # Parse and execute tool calls
        try:
            tool_calls = parse_tool_calls(response_text)
            if tool_calls:
                self._add_message("SYSTEM", "<b>Executing Tools...</b>", True)
                tool_outputs = []
                executed_count = 0
                cumulative_len = 0
                for call in tool_calls:
                    tool_name = call.get("tool_name")
                    args = call.get("args", [])
                    
                    if should_terminate:
                        tool_outputs.append(f"Skipped tool '{tool_name}': Termination sequence initiated by a previous tool.")
                        continue

                    if executed_count >= MAX_TOOL_CALLS or cumulative_len >= self.max_cumulative_tool_output:
                        reason = "COUNT_LIMIT" if executed_count >= MAX_TOOL_CALLS else "LENGTH_LIMIT"
                        # Dense error message for LLM consumption
                        fail_notice = f"[SYSTEM_ERROR] Tool '{tool_name}' with args: ({args}) is BLOCKED. Reason: {reason} ({cumulative_len} chars used). Retry with less tool calls."
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
        except Exception as e:
            self._add_message("SYSTEM", f"<i>Error parsing or executing tool calls: {html.escape(e)}</i>", True)
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
                from .summarizer import summarize_conversation
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
        '''Clear all history and plans'''
        # Remove all plans (if there are leftover)
        if self.agent_state.action_plans:
            try:
                self.agent_state.action_plans.clear()
                print("[AETHER Chatbot] All remaining action plans cleared.")
            except Exception as e:
                print(f"[AETHER Chatbot] Error clearing action plans: {e}")

        # Clear the conversation history entirely
        self.agent_state.conversation_history.clear()
        
    
    def _select_exposed_tools(self):
        """Launches the dialog to configure which tools are exposed to the AI."""
        # 1. Prepare input for the dialog (set of currently active tools)
        current_active_tools = {name for name, enabled in TOOL_CONFIG.items() if enabled}
        dlg = ToolSelectionDialog(current_active_tools, parent=self.parent)
        if dlg.exec_():
            new_enabled_tools_set = dlg.get_selected_tools()
            if current_active_tools == new_enabled_tools_set:
                return 1
            # 2. Convert the set of enabled names back to the required {name: True/False} dictionary
            new_tool_config = {}
            for tool_name in TOOL_REGISTRY.keys():
                tool_name_str = tool_name.value 
                new_tool_config[tool_name_str] = tool_name_str in new_enabled_tools_set
            # 3. Save
            if save_tool_config(new_tool_config):
                # 4. Update the in-memory state of the viewer after successful save
                self.exposed_tools = new_enabled_tools_set 
            else:
                print("Failed to save tool configuration. Check IDA output log.")
        return 1
    
    def _select_binary_functions_context(self) :
        select_context_functions(self)
        return 1
    
    def settle_manual_context(self) -> str:
        if not self.manual_context:
            return ""
            
        header = (
            "========================================\n"
            "[SYSTEM DIRECTIVE: REQUIRED CONTEXT]\n"
            "The user has manually designated the following binary functions as critical context. "
            "You must prioritize analyzing these functions, retrieve their data if necessary, "
            "and actively integrate their behavior into your reasoning for the subsequent query:\n\n"
        )
        
        # Use a list comprehension and join for cleaner string building
        func_lines = [
            f"  - Target Function: '{f['name']}' at address [{f['address']}]" 
            for f in self.manual_context
        ]
        functions_str = "\n".join(func_lines)
        
        footer = (
            "\n\n[END REQUIRED CONTEXT]\n"
            "Ensure the functions listed above form the core basis of your upcoming response.\n"
            "========================================\n\n"
        )
        
        return header + functions_str + footer

    def _stop_currrent_prompt(self):
        """Stops current prompt and breaks the thinking loop"""
        if not self.is_thinking:
            return
        self._cleanup()
        self._add_message("SYSTEM", "Force Stop Complete")
        print("[AETHER Chatbot] Force stop complete. Ready for new user query.")
        self.is_thinking = False
        self.force_stop = True
    
    def _refresh(self):
        global PERSISTENT_MESSAGE_LOG
        PERSISTENT_MESSAGE_LOG = []
        self.history_view.clear()
        self.agent_state.clear_memory()
        self.agent_state.conversation_history.clear()

    def _render_message(self, sender, message, is_html=False):
        """Handling HTML formatting"""
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
                <td width='20%'></td> </tr>
        </table>
        """
        self.history_view.append(full_html)
        self._scroll_to_bottom()

    def _add_message(self, sender, message, is_html=False):
        """Appends a message to the chat history"""
        global PERSISTENT_MESSAGE_LOG
        PERSISTENT_MESSAGE_LOG.append({"sender": sender, "msg": message})
        self._render_message(sender, message, is_html)
    
    def _scroll_to_bottom(self):
        cursor = self.history_view.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.history_view.setTextCursor(cursor)
    
    def _hide_search(self):
        self.search_bar.setVisible(False)
        self.history_view.setExtraSelections([]) # Clear highlights
        self.history_view.setFocus()

    def _show_search(self):
        self.search_bar.setVisible(True)
        self.search_bar.setFocus()
        if self.search_bar.search_input.text():
            self._do_search(self.search_bar.search_input.text())

    def _do_search(self, text, forward=True, is_next_call=False):
        if not text:
            self.history_view.setExtraSelections([])
            self.search_bar.update_counter(0, 0)
            return

        flags = QtGui.QTextDocument.FindFlags()
        if not forward:
            flags = QtGui.QTextDocument.FindBackward

        # --- THE FIX: The Nudge ---
        # If this was triggered by Enter/Shift+Enter (is_next_call), 
        # move the cursor by 1 char so find() doesn't hit the same spot.
        if is_next_call:
            cursor = self.history_view.textCursor()
            if forward:
                # Move forward 1 to get past the current match start
                cursor.movePosition(QtGui.QTextCursor.Right)
            else:
                # Move backward 1 to get behind the current match end
                cursor.movePosition(QtGui.QTextCursor.Left)
            self.history_view.setTextCursor(cursor)

        # 1. Perform the find
        found = self.history_view.find(text, flags)
        
        # 2. Handle Wrap-around
        if not found:
            cursor = self.history_view.textCursor()
            cursor.movePosition(QtGui.QTextCursor.Start if forward else QtGui.QTextCursor.End)
            self.history_view.setTextCursor(cursor)
            found = self.history_view.find(text, flags)

        if found:
            # Collapse selection to remove the 'Grey' box
            cursor = self.history_view.textCursor()
            # Position logic for forward/backward
            pos = cursor.position() if forward else cursor.selectionStart()
            cursor.setPosition(pos) 
            self.history_view.setTextCursor(cursor)
            self.history_view.ensureCursorVisible()

        # 3. Update UI
        all_cursors = self._get_all_cursors(text)
        self.total_matches = len(all_cursors)
        self._update_current_index(text, all_cursors)
        self._highlight_all_occurrences(all_cursors)
    
    
    def _get_all_cursors(self, text):
        cursors = []
        doc = self.history_view.document()
        curr = QtGui.QTextCursor(doc)
        while True:
            curr = doc.find(text, curr)
            if curr.isNull():
                break
            cursors.append(QtGui.QTextCursor(curr))
        return cursors
    
    def _update_current_index(self, text, cursors):
        if self.total_matches == 0:
            self.current_match_idx = 0
            return

        current_pos = self.history_view.textCursor().position()
        self.current_match_idx = 0
        
        for i, c in enumerate(cursors):
            # Check if the ghost cursor is at the start OR end of the match range
            if c.selectionStart() <= current_pos <= c.selectionEnd():
                self.current_match_idx = i + 1
                break
        
        self.search_bar.update_counter(self.current_match_idx, self.total_matches)

    def _highlight_all_occurrences(self, cursors):
        extra_selections = []
        
        # Base Yellow
        fmt = QtGui.QTextCharFormat()
        fmt.setBackground(QtGui.QColor("#fff34d"))
        
        # Active Orange
        current_fmt = QtGui.QTextCharFormat()
        current_fmt.setBackground(QtGui.QColor("#ff9d00"))

        # Current "Ghost" cursor position
        current_pos = self.history_view.textCursor().position()

        for c in cursors:
            selection = QtWidgets.QTextEdit.ExtraSelection()
            selection.cursor = c
            
            # If the cursor position falls within this match's range
            if c.selectionStart() <= current_pos <= c.selectionEnd():
                selection.format = current_fmt
            else:
                selection.format = fmt
                
            extra_selections.append(selection)
        
        self.history_view.setExtraSelections(extra_selections)

    def OnClose(self, form):
        """Called when the form is closed."""
        app = QtWidgets.QApplication.instance()
        if app is not None and self.theme_filter is not None:
            app.removeEventFilter(self.theme_filter)
            self.theme_filter = None
        self.is_running = False

    def Show(self):
        """Creates and shows the form."""
        res = super(ChatbotViewer, self).Show(
            CHATBOT_VIEW_TITLE,
            options=(ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WCLS_CLOSE_LATER)
        )
        if res:
            # Use the target title for docking (e.g., "Pseudocode-B")
            ida_kernwin.set_dock_pos(CHATBOT_VIEW_TITLE, self.dock_target, ida_kernwin.DP_RIGHT)
        return res

class ToolSelectionDialog(QtWidgets.QDialog):
    """Dialog for selecting which AETHER tools the LLM can use."""
    def __init__(self, current_active_tools: set, parent=None):
        super(ToolSelectionDialog, self).__init__(parent)
        self.setWindowTitle("AETHER Tool Exposure Configuration")
        self.setMinimumSize(400, 500)
        self.tool_checkboxes = {}
        self.active_tools = current_active_tools # e.g., {'add_action_plan', 'list_functions'}
        
        layout = QtWidgets.QVBoxLayout()
        
        header_label = QtWidgets.QLabel("Select which tools the AI agent should have access to:")
        header_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        # Scroll area for the tool list
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        tools_container = QtWidgets.QWidget()
        tools_layout = QtWidgets.QVBoxLayout(tools_container)
        tools_layout.setAlignment(QtCore.Qt.AlignTop)

        # Populate tool list from ToolNames enum
        for tool_name in TOOL_REGISTRY:
            checkbox = QtWidgets.QCheckBox(tool_name.value)
            
            # Check the box if the tool is in the current active set
            if tool_name.value in self.active_tools:
                checkbox.setChecked(True)
                
            self.tool_checkboxes[tool_name.value] = checkbox
            tools_layout.addWidget(checkbox)

        scroll_area.setWidget(tools_container)
        layout.addWidget(scroll_area)
        
        # Buttons layout
        button_layout = QtWidgets.QHBoxLayout()
        
        self.select_all_button = QtWidgets.QPushButton("Select All")
        self.select_all_button.clicked.connect(self.select_all)
        button_layout.addWidget(self.select_all_button)
        
        self.deselect_all_button = QtWidgets.QPushButton("Deselect All")
        self.deselect_all_button.clicked.connect(self.deselect_all)
        button_layout.addWidget(self.deselect_all_button)
        
        button_layout.addStretch()
        
        self.ok_button = QtWidgets.QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        button_layout.addWidget(self.ok_button)
        
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def select_all(self):
        """Sets all checkboxes to checked."""
        for checkbox in self.tool_checkboxes.values():
            checkbox.setChecked(True)

    def deselect_all(self):
        """Sets all checkboxes to unchecked."""
        for checkbox in self.tool_checkboxes.values():
            checkbox.setChecked(False)

    def get_selected_tools(self) -> set:
        """Returns a set of strings of the tool names that are checked."""
        selected = set()
        for name, checkbox in self.tool_checkboxes.items():
            if checkbox.isChecked():
                selected.add(name)
        return selected

class SearchBarWidget(QtWidgets.QFrame):
    """A floating-style search bar for the history view."""
    next_clicked = QtCore.pyqtSignal(str)
    prev_clicked = QtCore.pyqtSignal(str)
    close_clicked = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Find...")
        self.search_input.installEventFilter(self) # For Enter/Shift+Enter

        # Counter label
        self.counter_label = QtWidgets.QLabel("0/0")
        self.counter_label.setStyleSheet("font-size: 9pt; border: none;")
        
        self.close_btn = QtWidgets.QPushButton("✕")
        self.close_btn.setFixedSize(20, 20)
        self.close_btn.setStyleSheet("border: none; color: #888; font-weight: bold;")
        self.close_btn.clicked.connect(self.close_clicked)

        layout.addWidget(self.search_input)
        layout.addWidget(self.counter_label)
        layout.addWidget(self.close_btn)

        palette = self.palette()
        self.apply_theme_styles(
            window_color=palette.color(QtGui.QPalette.Window).name(),
            base_color=palette.color(QtGui.QPalette.Base).name(),
            text_color=palette.color(QtGui.QPalette.Text).name(),
            mid_color=palette.color(QtGui.QPalette.Mid).name(),
        )

    def apply_theme_styles(self, window_color: str, base_color: str, text_color: str, mid_color: str):
        self.setStyleSheet(f"""
            SearchBarWidget {{
                background: {window_color};
                border: 1px solid {mid_color};
                border-radius: 4px;
            }}
            QLineEdit {{
                background: {base_color};
                color: {text_color};
                border: none;
                padding: 2px;
            }}
            QLabel {{
                color: {text_color};
            }}
            QPushButton {{
                border: none;
                color: {text_color};
                font-weight: bold;
            }}
        """)
    
    def update_counter(self, current, total):
        self.counter_label.setText(f"{current}/{total}" if total > 0 else "0/0")

    def eventFilter(self, obj, event):
        if obj is self.search_input and event.type() == QtCore.QEvent.KeyPress:
            if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if event.modifiers() & QtCore.Qt.ShiftModifier:
                    self.prev_clicked.emit(self.search_input.text())
                else:
                    self.next_clicked.emit(self.search_input.text())
                return True
        return super().eventFilter(obj, event)

    def setFocus(self):
        self.search_input.setFocus()
class EscapeEventFilter(QtCore.QObject):
    """A cross-compatible event filter to trap the Escape key."""
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress:
            # Handle Escape key
            if event.key() == QtCore.Qt.Key_Escape:
                # If search bar is open, close it
                if hasattr(self.owner, 'search_bar') and self.owner.search_bar.isVisible():
                    self.owner._hide_search()
                else:
                    print("[AETHER] Escape key suppressed.")
                return True # Consume the event
        return False


class ThemeRefreshEventFilter(QtCore.QObject):
    """Watches for global style/palette changes and triggers a refresh callback."""
    def __init__(self, refresh_callback):
        super().__init__()
        self.refresh_callback = refresh_callback

    def eventFilter(self, obj, event):
        if event.type() in (
            QtCore.QEvent.ApplicationPaletteChange,
            QtCore.QEvent.PaletteChange,
            QtCore.QEvent.StyleChange,
        ):
            self.refresh_callback()
        return False

def show_chatbot_viewer(dock_target="Pseudocode-A"):
    """
    Creates and shows a new instance of the chatbot viewer.
    Opens to the right of pseudocode view.
    """
    widget = ida_kernwin.find_widget(CHATBOT_VIEW_TITLE)
    if widget:
        ida_kernwin.activate_widget(widget, True)
    else:
        viewer = ChatbotViewer(dock_target=dock_target)
        viewer.Show()

if __name__ == "__main__":
    # For testing purposes
    show_chatbot_viewer()