# Chatbot Context Menu Function Reference

This document covers every function currently defined in:
- `plugin/ainalyse/chatbot/ui/context_menu.py`
- `plugin/ainalyse/chatbot/context_menu_controller.py`

## Shared Parameter Convention
Many functions accept `CBController`.
`CBController` is expected to be an instance of `ChatbotController`

## File: `ui/context_menu.py`

### Class `ChatbotContextMenu`

<!-- #### `__init__(self)`
- Parameters:
  - `self`: Class instance.
Class Initialisation. -->

#### `_show_context_menu(CBController, position)` (staticmethod)
- Parameters:
  - `CBController`: Controller object providing UI references and callbacks.
  - `position`: Local viewport position from `customContextMenuRequested`.
- Returns:
  - None.
- Use case:
  - Builds and shows the right-click menu in chatbot history view.
  - Preserves default QTextEdit menu actions, then appends chatbot-specific actions.
- Uses:
  - `QtWidgets.QMenu`
  - `CBController.history_view.createStandardContextMenu()`
  - Controller callbacks:
    - `CBController._show_search`
    - `CBController._refresh`
    - `CBController._select_exposed_tools`
    - `CBController._select_binary_functions_context`
    - `CBController._stop_currrent_prompt`
  - `menu.exec_(global_pos)` for modal popup execution.
- Typical caller:
  - Connected in `viewer.py` from `history_view.customContextMenuRequested`.

## File: `context_menu_controller.py`

### Class `SearchText`

#### `__init__(self)`
- Parameters:
  - `self`: Class instance.
- Returns:
  - None.
- Use case:
  - Placeholder constructor; class is used via static methods.

#### `hide_search(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `search_bar` and `history_view`.
- Returns:
  - None.
- Use case:
  - Hides search UI and clears text highlight selections.
- Uses:
  - `CBController.search_bar.setVisible(False)`
  - `CBController.history_view.setExtraSelections([])`
  - `CBController.history_view.setFocus()`

#### `show_search(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `search_bar` and `history_view`.
- Returns:
  - None.
- Use case:
  - Shows search bar and immediately performs search if input already exists.
- Uses:
  - `SearchText.do_search(...)` when search text is non-empty.

#### `do_search(CBController, text, forward=True, is_next_call=False)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `history_view`, `search_bar`, match counters.
  - `text`: Query string.
  - `forward`: Search direction; `True` for next, `False` for previous.
  - `is_next_call`: If `True`, nudges cursor before searching to move to next/previous occurrence.
- Returns:
  - None.
- Use case:
  - Performs wrapped find operation in chat history and refreshes highlights/counters.
- Uses:
  - `QTextDocument.FindFlags` and `FindBackward`
  - `history_view.find(...)`
  - Internal helpers:
    - `_get_all_cursors(...)`
    - `_update_current_index(...)`
    - `_highlight_all_occurrences(...)`

#### `_get_all_cursors(CBController, text)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `history_view`.
  - `text`: Query string.
- Returns:
  - `list[QTextCursor]`: Cursors for all matches.
- Use case:
  - Scans the full chat document and collects all match ranges.
- Uses:
  - `doc.find(text, curr)` loop until null cursor.

#### `_update_current_index(CBController, cursors)` (staticmethod)
- Parameters:
  - `CBController`: Controller with cursor position and search counter UI.
  - `cursors`: List of all match cursors.
- Returns:
  - None.
- Use case:
  - Updates current match index based on the active text cursor and refreshes visual counter.
- Uses:
  - `CBController.search_bar.update_counter(current, total)`

#### `_highlight_all_occurrences(CBController, cursors)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `history_view`.
  - `cursors`: List of match cursors.
- Returns:
  - None.
- Use case:
  - Highlights all search hits, with a distinct color for the current active hit.
- Uses:
  - `QtWidgets.QTextEdit.ExtraSelection`
  - Yellow for non-current (`#fff34d`) and orange for current (`#ff9d00`).

### Class `ClearChatHistory`

#### `__init__(self)`
- Parameters:
  - `self`: Class instance.
- Returns:
  - None.
- Use case:
  - Placeholder constructor; class is used via static methods.

#### `clear_chat_history(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller with message log, view, and agent state.
- Returns:
  - None.
- Use case:
  - Clears persistent/logged messages, clears visible chat, and resets memory/conversation history.
- Uses:
  - `CBController.PERSISTENT_MESSAGE_LOG.clear()`
  - `CBController.history_view.clear()`
  - `CBController.agent_state.clear_memory()`
  - `CBController.agent_state.conversation_history.clear()`

### Class `SelectExposedTools`

#### `__init__(self)`
- Parameters:
  - `self`: Class instance.
- Returns:
  - None.
- Use case:
  - Placeholder constructor; class is used via static methods.

#### `select_exposed_tools(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `parent` and `exposed_tools`.
- Returns:
  - `1` in all code paths.
- Use case:
  - Opens tool-selection dialog, computes enabled tools, persists new config, and updates controller state.
- Uses:
  - `TOOL_CONFIG` to compute currently enabled tools.
  - `ToolSelectionDialog(current_active_tools, parent=CBController.parent)`
  - `TOOL_REGISTRY` to build full bool map for saving.
  - `save_tool_config(new_tool_config)`
  - Updates `CBController.exposed_tools` on successful save.

### Constant `MAX_CONTEXT_FUNCTIONS`
- Value:
  - `50`
- Use case:
  - Upper bound for manually selected context functions.

### Class `SelectBinaryFunctionsContext`

#### `__init__(self)`
- Parameters:
  - `self`: Class instance.
- Returns:
  - None.
- Use case:
  - Placeholder constructor; class is used via static methods.

#### `get_current_function_name(show_warning=False)` (staticmethod)
- Parameters:
  - `show_warning`: If `True`, emits IDA warning and console logs on failure.
- Returns:
  - Tuple `(func_name, func_addr, flag)` where:
    - success: `(str, str, True)`
    - failure: `(-1, -1, False)`
- Use case:
  - Resolves current function from screen EA, with fallback to first function in the binary.
- Uses:
  - `ida_kernwin.get_screen_ea()`
  - `idaapi.get_func(ea)`
  - `idautils.Functions()` fallback
  - `ida_funcs.get_func_name(...)`
  - `ida_kernwin.warning(...)` for user-facing warnings.

#### `select_binary_functions_context(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller with `parent`, `manual_context`, and `_refresh_context_pills()`.
- Returns:
  - None.
- Use case:
  - Shows function selection dialog for manual context injection.
  - Applies limits and updates pills UI.
- Uses:
  - `get_current_function_name(show_warning=True)`
  - `FunctionSelectionDialog(..., onlyTopLevel=True)`
  - `dlg.get_selected_functions()`
  - Truncation to `MAX_CONTEXT_FUNCTIONS`
  - `CBController._refresh_context_pills()`

#### `settle_manual_context(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller containing `manual_context`.
- Returns:
  - `str`: Prompt preface for LLM, or empty string if no context selected.
- Use case:
  - Converts selected manual context into a strict system directive block prepended to user input.
- Uses:
  - Builds multiline text containing selected function names and addresses.
  - Includes note about `aire`-prefixed renamed functions.

### Class `StopCurrentPrompt`

#### `__init__(self)`
- Parameters:
  - `self`: Class instance.
- Returns:
  - None.
- Use case:
  - Placeholder constructor; class is used via static methods.

#### `stop_current_prompt(CBController)` (staticmethod)
- Parameters:
  - `CBController`: Controller with runtime loop state and message methods.
- Returns:
  - None.
- Use case:
  - Force-stops the current chatbot run if one is active.
- Uses:
  - Early return when `CBController.is_thinking` is false.
  - `CBController._cleanup()`
  - `CBController._add_message("SYSTEM", "Force Stop Complete")`
  - Sets:
    - `CBController.is_thinking = False`
    - `CBController.force_stop = True`

## Verified Wiring Summary

- Context menu entry point:
  - `ui/viewer.py` connects right-click to `ChatbotContextMenu._show_context_menu(...)`.
- Controller delegates:
  - `controller.py` exposes wrappers (`_show_search`, `_refresh`, `_select_exposed_tools`, `_select_binary_functions_context`, `_stop_currrent_prompt`, `settle_manual_context`) that dispatch into `context_menu_controller.py` classes.

## Notes

- Many classes in these files are static utility containers; `__init__` methods are currently no-op placeholders.
- The menu label `"Manually Select Available Functions"` currently triggers tool exposure selection, not binary-function context selection.
