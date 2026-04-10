# Main Chatbot UI and Controller Function Documentation

This document covers every function currently defined in:
- `plugin/ainalyse/chatbot/ui/viewer.py`
- `plugin/ainalyse/chatbot/controller.py`

It is based on the current code in this workspace.

## File: `ui/viewer.py`

### Constant

#### `CHATBOT_VIEW_TITLE`
- Value: `"AETHER Chatbot"`
- Use case: Window/widget title used by `PluginForm.Show()` and widget lookup in `show_chatbot_viewer()`.

### Class `ChatInputBox(QtWidgets.QTextEdit)`

#### `__init__(self, parent=None)`
- Parameters:
  - `self`: ChatInputBox instance.
  - `parent`: Optional Qt parent widget.
- Returns: None.
- Use case: Initializes input box behavior for chat sending.
- Uses:
  - Sets placeholder and min/max heights.
  - Connects `textChanged` and document size change to `adjust_height()`.
  - Defines dynamic height from 30 to 150 px.

#### `adjust_height(self)`
- Parameters:
  - `self`: ChatInputBox instance.
- Returns: None.
- Use case: Auto-resizes input widget to content height, enabling vertical scrollbar when max height is reached.
- Uses:
  - `self.document().size().height()`
  - `self.setFixedHeight(...)`
  - `self.setVerticalScrollBarPolicy(...)`

#### `keyPressEvent(self, event)`
- Parameters:
  - `self`: ChatInputBox instance.
  - `event`: Qt key event.
- Returns: None.
- Use case:
  - `Enter` sends message (`returnPressed.emit()`).
  - `Shift+Enter` inserts newline.
- Uses:
  - Emits custom signal `returnPressed`.
  - Falls back to superclass handler for non-send behavior.

### Class `FlowLayout(QtWidgets.QLayout)`

#### `__init__(self, parent=None, margin=0, spacing=-1)`
- Parameters:
  - `self`: FlowLayout instance.
  - `parent`: Optional Qt parent.
  - `margin`: Layout margins.
  - `spacing`: Item spacing.
- Returns: None.
- Use case: Creates a wrapping flow layout used for context pills.

#### `__del__(self)`
- Parameters:
  - `self`: FlowLayout instance.
- Returns: None.
- Use case: Clears layout items during object destruction.

#### `addItem(self, item)`
- Parameters:
  - `self`: FlowLayout instance.
  - `item`: `QLayoutItem` to add.
- Returns: None.
- Use case: Appends an item into internal `itemList`.

#### `count(self)`
- Parameters:
  - `self`: FlowLayout instance.
- Returns:
  - `int`: Number of items.
- Use case: Qt layout API implementation.

#### `itemAt(self, index)`
- Parameters:
  - `self`: FlowLayout instance.
  - `index`: Item index.
- Returns:
  - `QLayoutItem` or `None`.
- Use case: Safe indexed accessor for Qt layout API.

#### `takeAt(self, index)`
- Parameters:
  - `self`: FlowLayout instance.
  - `index`: Item index.
- Returns:
  - Removed `QLayoutItem` or `None`.
- Use case: Removes an item by index for Qt layout API.

#### `expandingDirections(self)`
- Parameters:
  - `self`: FlowLayout instance.
- Returns:
  - Qt orientation flags (no expansion preference).
- Use case: Qt layout behavior declaration.

#### `hasHeightForWidth(self)`
- Parameters:
  - `self`: FlowLayout instance.
- Returns:
  - `True`.
- Use case: Indicates layout height depends on available width.

#### `heightForWidth(self, width)`
- Parameters:
  - `self`: FlowLayout instance.
  - `width`: Available width.
- Returns:
  - `int`: Computed height.
- Use case: Calculates needed height for wrapping layout.
- Uses:
  - Delegates to `_doLayout(..., testOnly=True)`.

#### `setGeometry(self, rect)`
- Parameters:
  - `self`: FlowLayout instance.
  - `rect`: Target geometry rectangle.
- Returns: None.
- Use case: Applies geometry and lays out children.
- Uses:
  - Calls `_doLayout(..., testOnly=False)`.

#### `sizeHint(self)`
- Parameters:
  - `self`: FlowLayout instance.
- Returns:
  - `QSize`: Suggested size.
- Use case: Qt layout hint.
- Uses:
  - Returns `minimumSize()`.

#### `minimumSize(self)`
- Parameters:
  - `self`: FlowLayout instance.
- Returns:
  - `QSize`.
- Use case: Calculates minimum layout size from child minimum sizes and margins.

#### `_doLayout(self, rect, testOnly)`
- Parameters:
  - `self`: FlowLayout instance.
  - `rect`: Available rectangle.
  - `testOnly`: If `True`, compute only; if `False`, set child geometries.
- Returns:
  - `int`: Height used.
- Use case: Core wrapping algorithm for pill placement.

### Class `SearchBarWidget(QtWidgets.QFrame)`

#### `__init__(self, parent=None)`
- Parameters:
  - `self`: SearchBarWidget instance.
  - `parent`: Optional Qt parent.
- Returns: None.
- Use case: Builds search bar with input, counter, and close button.
- Uses:
  - Sets stylesheet and layout.
  - Registers event filter on `search_input`.
  - Emits signals through button/key handling.

#### `update_counter(self, current, total)`
- Parameters:
  - `self`: SearchBarWidget instance.
  - `current`: Current match index.
  - `total`: Total match count.
- Returns: None.
- Use case: Updates `x/y` search counter display.

#### `eventFilter(self, obj, event)`
- Parameters:
  - `self`: SearchBarWidget instance.
  - `obj`: Event source object.
  - `event`: Qt event.
- Returns:
  - `True` if handled, otherwise superclass result.
- Use case:
  - Handles Enter key in search input.
  - `Enter` emits `next_clicked`.
  - `Shift+Enter` emits `prev_clicked`.

#### `setFocus(self)`
- Parameters:
  - `self`: SearchBarWidget instance.
- Returns: None.
- Use case: Focuses the internal line edit (`search_input`).

### Class `EscapeEventFilter(QtCore.QObject)`

#### `__init__(self, owner)`
- Parameters:
  - `self`: EscapeEventFilter instance.
  - `owner`: `ChatbotViewer` owner.
- Returns: None.
- Use case: Stores owner so Escape can hide search bar through controller.

#### `eventFilter(self, obj, event)`
- Parameters:
  - `self`: EscapeEventFilter instance.
  - `obj`: Event source.
  - `event`: Qt event.
- Returns:
  - `True` when Escape is handled, otherwise `False`.
- Use case:
  - If Escape is pressed and search bar is visible, calls `owner.controller._hide_search()`.

### Class `ChatbotViewer(ida_kernwin.PluginForm)`

#### `__init__(self, dock_target="Pseudocode-A")`
- Parameters:
  - `self`: ChatbotViewer instance.
  - `dock_target`: IDA dock target name.
- Returns: None.
- Use case: Creates viewer and its `ChatbotController`.

#### `OnCreate(self, form)`
- Parameters:
  - `self`: ChatbotViewer instance.
  - `form`: IDA form handle.
- Returns: None.
- Use case: PluginForm lifecycle hook; converts form to Qt widget and initializes UI.
- Uses:
  - `self.FormToPyQtWidget(form)`
  - `self._init_ui(parent)`

#### `OnClose(self, form)`
- Parameters:
  - `self`: ChatbotViewer instance.
  - `form`: IDA form handle.
- Returns: None.
- Use case: PluginForm lifecycle hook; requests controller loop stop (`is_running = False`).

#### `Show(self)`
- Parameters:
  - `self`: ChatbotViewer instance.
- Returns:
  - PluginForm show result.
- Use case: Shows/docks chatbot panel in IDA.
- Uses:
  - `ida_kernwin.PluginForm.Show(...)`
  - `ida_kernwin.set_dock_pos(...)` when show succeeds.

#### `_init_ui(self, parent)`
- Parameters:
  - `self`: ChatbotViewer instance.
  - `parent`: Parent Qt widget from IDA form.
- Returns: None.
- Use case: Builds full chatbot UI and wires all signals to controller actions.
- Uses:
  - Creates `SearchBarWidget`, `QTextEdit` history, context section, pills flow area, and `ChatInputBox`.
  - Context menu hookup: `ChatbotContextMenu._show_context_menu(self.controller, pos)`.
  - Search hookups:
    - next/prev -> `controller._do_search(...)`
    - close -> `controller._hide_search`
    - textChanged -> `controller._do_search`
  - Message send hookup: `input_box.returnPressed -> controller.send_message`
  - Context button hookup: `context_gear_btn.clicked -> controller._on_context_gear_clicked`
  - Binds widgets into controller via `controller.bind_widgets(...)`.
  - Calls `controller._refresh_context_pills()` for initial state.

### Module Function

#### `show_chatbot_viewer(dock_target="Pseudocode-A")`
- Parameters:
  - `dock_target`: IDA docking target.
- Returns: None.
- Use case: Ensures only one chatbot widget is active; activates existing or creates/shows new one.
- Uses:
  - `ida_kernwin.find_widget(CHATBOT_VIEW_TITLE)`
  - `ida_kernwin.activate_widget(...)`
  - `ChatbotViewer(...).Show()`

## File: `controller.py`

### Class `ChatbotController`

#### `__init__(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Initializes persistent state, UI references, async queue, context/search state, and tool limits.
- Uses:
  - `AgentState()` for persistent agent state.
  - `self._load_base_prompt()`.
  - `queue.Queue()` for thread-safe message passing.
  - `TOOL_CONFIG` to derive enabled tools.

#### `bind_widgets(self, parent, main_widget, history_view, input_box, context_frame, context_gear_btn, pills_scroll, pills_container, pills_layout, search_bar)`
- Parameters:
  - `self`: ChatbotController instance.
  - `parent`: Top-level parent widget.
  - `main_widget`: Main container widget.
  - `history_view`: QTextEdit for chat transcript.
  - `input_box`: Chat input widget.
  - `context_frame`: Context area frame.
  - `context_gear_btn`: Context picker button.
  - `pills_scroll`: Scroll area for context pills.
  - `pills_container`: Pills container widget.
  - `pills_layout`: Flow layout for pills.
  - `search_bar`: Search bar widget.
- Returns: None.
- Use case: Stores UI widget references used across controller methods.

#### `_load_base_prompt(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns:
  - `str`: Evaluated base prompt or fallback prompt string on error.
- Use case: Loads and f-string-evaluates `prompts/base_chat.txt` with safe globals (`ToolNames`, `TaskStatus`).

#### `_on_context_gear_clicked(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Context gear button handler; opens manual binary context selector.
- Uses:
  - Calls `_select_binary_functions_context()`.

#### `_refresh_context_pills(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Rebuilds context pill UI from `manual_context` list.
- Uses:
  - Clears existing pills.
  - Creates clickable `QPushButton` per function.
  - Click removes corresponding pill via `_remove_context_pill(idx)`.
  - Stops rendering if selected context exceeds `MAX_CONTEXT_FUNCTIONS`.

#### `_remove_context_pill(self, idx)`
- Parameters:
  - `self`: ChatbotController instance.
  - `idx`: Index into `manual_context`.
- Returns: None.
- Use case: Removes selected context item and refreshes pills display.

#### `_scroll_to_bottom(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Moves transcript cursor to end after appending content.

#### `_render_message(self, sender, message, is_html=False)`
- Parameters:
  - `self`: ChatbotController instance.
  - `sender`: Message label (`You`, `AETHER`, `SYSTEM`, etc.).
  - `message`: Message body.
  - `is_html`: Whether message is trusted HTML.
- Returns: None.
- Use case: Renders a message row into chat history with HTML table layout.
- Uses:
  - Escapes content with `html.escape(...)` unless `is_html=True`.
  - Calls `_scroll_to_bottom()`.

#### `_add_message(self, sender, message, is_html=False)`
- Parameters:
  - `self`: ChatbotController instance.
  - `sender`: Message label.
  - `message`: Message body.
  - `is_html`: Whether message is trusted HTML.
- Returns: None.
- Use case: Adds message to persistent log and renders to history view.

#### `send_message(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Entry point when user submits prompt.
- Uses:
  - Reads and validates input.
  - Adds user message to UI/log.
  - Enqueues packet: `{"type": "user_input", "content": self._settle_manual_context() + user_message}`.
  - Clears manual context and refreshes pills.
  - Starts agent response when idle.

#### `_trigger_agent_response(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Adds Thinking status and starts async pipeline processing.
- Uses:
  - `start_pipeline(self._process_message_thread())`.

#### `_process_message_thread(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns:
  - Async coroutine (no explicit value).
- Use case: Main agent loop handling queued user/tool messages and LLM interactions.
- Uses:
  - Decorated by `@use_async_worker(name="AetherAgent")`.
  - Pulls queue items via `await asyncio.to_thread(self.message_queue.get)`.
  - Builds prompt state and message list.
  - Executes `_llm_call` in thread via `asyncio.to_thread`.
  - Processes response with `_handle_llm_response`.
  - Triggers mid-conversation summarization when limits are reached.
  - On error, logs system message through `_execute_ui_sync(...)` and marks thinking false.
  - Calls `self.message_queue.task_done()` in `finally`.

#### `_llm_call(self, messages)`
- Parameters:
  - `self`: ChatbotController instance.
  - `messages`: Chat-completions message list.
- Returns:
  - `str`: Trimmed assistant response text.
- Use case: Performs model call with retries and timeout.
- Uses:
  - `create_openai_client_with_custom_ca(...)`
  - `client.chat.completions.create(...)`
  - Retry count from `CHATBOT_CONNECTION_RETRIES` (default 2).
  - Timeout from `CHATBOT_REQUEST_TIMEOUT` (default 120 sec).
  - Raises `RuntimeError` after final failed attempt.

#### `_execute_ui_sync(self, fn, flags=ida_kernwin.MFF_WRITE)`
- Parameters:
  - `self`: ChatbotController instance.
  - `fn`: Callable to execute on IDA main thread.
  - `flags`: `execute_sync` mode flags.
- Returns:
  - Return value produced by `fn`.
- Use case: Safe helper for main-thread UI operations from worker contexts.
- Uses:
  - `ida_kernwin.execute_sync(...)`.

#### `_build_tool_prompt(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns:
  - `str`: Dynamic section describing enabled and disabled tools.
- Use case: Appends tool availability status to system prompt.
- Uses:
  - `TOOL_REGISTRY` and `self.exposed_tools`.

#### `_handle_llm_response(self, response_text: str)`
- Parameters:
  - `self`: ChatbotController instance.
  - `response_text`: Raw LLM output text.
- Returns:
  - `bool`: `True` when conversation should terminate, else `False`.
- Use case: Parses tool calls, executes tools, enqueues tool outputs, and decides termination/finalization.
- Uses:
  - `parse_tool_calls(response_text)`.
  - UI updates via `_execute_ui_sync(...)`.
  - Tool dispatch via `TOOL_REGISTRY[tool_name](self.agent_state, *args)`.
  - Guardrails:
    - max tool calls (`MAX_TOOL_CALLS`)
    - cumulative output budget (`self.max_cumulative_tool_output`)
  - Enqueues tool output packet when needed.
  - Calls `_finalize_conversation()` when `should_terminate`.

#### `_finalize_conversation(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Triggers async final summary and cleans up UI/state on completion.
- Uses:
  - Schedules nested coroutine `run_finalization()` using `schedule_ui_task(...)`.

##### Local function `run_finalization()` (inside `_finalize_conversation`)
- Parameters: None.
- Returns: Async coroutine result (no explicit value).
- Use case: Awaits final conversation summary and applies UI updates on main thread.
- Uses:
  - `summarize_conversation(self.agent_state, finalize=True)`.
  - `ida_kernwin.execute_sync(...)`.

##### Local function `update_ui_sync()` (inside `run_finalization`)
- Parameters: None.
- Returns: None.
- Use case: Adds final summary message, runs cleanup, marks completion, and resets `is_thinking`.

#### `_cleanup(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Clears remaining action plans and conversation history.

#### `_select_exposed_tools(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns:
  - `1`.
- Use case: Delegates to context-menu controller for tool exposure settings.
- Uses:
  - `SelectExposedTools.select_exposed_tools(self)`.

#### `_select_binary_functions_context(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns:
  - `1`.
- Use case: Delegates to context-menu controller for manual binary context selection.
- Uses:
  - `SelectBinaryFunctionsContext.select_binary_functions_context(self)`.

#### `_settle_manual_context(self) -> str`
- Parameters:
  - `self`: ChatbotController instance.
- Returns:
  - `str`: Prompt prefix describing required manual context.
- Use case: Delegates manual context serialization to context-menu controller utility.
- Uses:
  - `SelectBinaryFunctionsContext.settle_manual_context(self)`.

#### `_stop_currrent_prompt(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Delegates force-stop behavior.
- Uses:
  - `StopCurrentPrompt.stop_current_prompt(self)`.

#### `_refresh(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Delegates chat-history reset behavior.
- Uses:
  - `ClearChatHistory.clear_chat_history(self)`.

#### `_hide_search(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Delegates hiding search bar and clearing highlights.
- Uses:
  - `SearchText.hide_search(self)`.

#### `_show_search(self)`
- Parameters:
  - `self`: ChatbotController instance.
- Returns: None.
- Use case: Delegates showing/focusing search UI.
- Uses:
  - `SearchText.show_search(self)`.

#### `_do_search(self, text)`
- Parameters:
  - `self`: ChatbotController instance.
  - `text`: Search query.
- Returns: None.
- Use case: Delegates transcript search/highlight update.
- Uses:
  - `SearchText.do_search(self, text)`.

## Cross-File Wiring Summary

- `viewer.py` owns UI construction and emits user interaction events.
- `controller.py` owns message processing, async orchestration, model/tool execution, and delegates context menu/search utilities to `context_menu_controller.py`.
- `show_chatbot_viewer()` is the module-level entry point for bringing up or focusing the chatbot panel.

## Notes

- `context_gear_btn.clicked` is connected to `_on_context_gear_clicked` twice in `_init_ui`; both connections target the same action.
- Method name `_stop_currrent_prompt` intentionally keeps triple `r` to match existing callback wiring.
