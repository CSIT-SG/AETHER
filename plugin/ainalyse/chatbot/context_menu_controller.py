from PyQt5 import QtGui, QtWidgets

import ida_kernwin, idautils, idaapi, ida_funcs
from ainalyse.function_selection import FunctionSelectionDialog
from .backend.toolselectiondialog import ToolSelectionDialog
from .backend.toolconfig import TOOL_CONFIG, save_tool_config
from .backend.tools import TOOL_REGISTRY

class SearchText :
    def __init__(self) : pass

    @staticmethod
    def hide_search(CBController):
        if CBController.search_bar is None:
            return
        CBController.search_bar.setVisible(False)
        CBController.history_view.setExtraSelections([])
        CBController.history_view.setFocus()

    @staticmethod
    def show_search(CBController):
        if CBController.search_bar is None:
            return
        CBController.search_bar.setVisible(True)
        CBController.search_bar.setFocus()
        if CBController.search_bar.search_input.text():
            SearchText.do_search(CBController, CBController.search_bar.search_input.text())

    @staticmethod
    def do_search(CBController, text, forward=True, is_next_call=False):
        if not text:
            CBController.history_view.setExtraSelections([])
            CBController.search_bar.update_counter(0, 0)
            return

        flags = QtGui.QTextDocument.FindFlags()
        if not forward:
            flags = QtGui.QTextDocument.FindBackward

        if is_next_call:
            cursor = CBController.history_view.textCursor()
            cursor.movePosition(QtGui.QTextCursor.Right if forward else QtGui.QTextCursor.Left)
            CBController.history_view.setTextCursor(cursor)

        found = CBController.history_view.find(text, flags)
        if not found:
            cursor = CBController.history_view.textCursor()
            cursor.movePosition(QtGui.QTextCursor.Start if forward else QtGui.QTextCursor.End)
            CBController.history_view.setTextCursor(cursor)
            found = CBController.history_view.find(text, flags)

        if found:
            cursor = CBController.history_view.textCursor()
            pos = cursor.position() if forward else cursor.selectionStart()
            cursor.setPosition(pos)
            CBController.history_view.setTextCursor(cursor)
            CBController.history_view.ensureCursorVisible()

        all_cursors = SearchText._get_all_cursors(CBController, text)
        CBController.total_matches = len(all_cursors)
        SearchText._update_current_index(CBController, all_cursors)
        SearchText._highlight_all_occurrences(CBController, all_cursors)

    @staticmethod
    def _get_all_cursors(CBController, text):
        cursors = []
        doc = CBController.history_view.document()
        curr = QtGui.QTextCursor(doc)
        while True:
            curr = doc.find(text, curr)
            if curr.isNull():
                break
            cursors.append(QtGui.QTextCursor(curr))
        return cursors

    @staticmethod
    def _update_current_index(CBController, cursors):
        if CBController.total_matches == 0:
            CBController.current_match_idx = 0
            return

        current_pos = CBController.history_view.textCursor().position()
        CBController.current_match_idx = 0
        for i, c in enumerate(cursors):
            if c.selectionStart() <= current_pos <= c.selectionEnd():
                CBController.current_match_idx = i + 1
                break
        CBController.search_bar.update_counter(CBController.current_match_idx, CBController.total_matches)

    @staticmethod
    def _highlight_all_occurrences(CBController, cursors):
        extra_selections = []
        fmt = QtGui.QTextCharFormat()
        fmt.setBackground(QtGui.QColor("#fff34d"))

        current_fmt = QtGui.QTextCharFormat()
        current_fmt.setBackground(QtGui.QColor("#ff9d00"))

        current_pos = CBController.history_view.textCursor().position()
        for c in cursors:
            selection = QtWidgets.QTextEdit.ExtraSelection()
            selection.cursor = c
            selection.format = current_fmt if c.selectionStart() <= current_pos <= c.selectionEnd() else fmt
            extra_selections.append(selection)
        CBController.history_view.setExtraSelections(extra_selections)

class ClearChatHistory :
    def __init__(self) : pass

    @staticmethod
    def clear_chat_history(CBController) :
        CBController.PERSISTENT_MESSAGE_LOG.clear()
        CBController.history_view.clear()
        CBController.agent_state.clear_memory()
        CBController.agent_state.conversation_history.clear()

class SelectExposedTools :
    def __init__(self) : pass

    @staticmethod
    def select_exposed_tools(CBController):
        current_active_tools = {name for name, enabled in TOOL_CONFIG.items() if enabled}
        dlg = ToolSelectionDialog(current_active_tools, parent=CBController.parent)
        if dlg.exec_():
            new_enabled_tools_set = dlg.get_selected_tools()
            if current_active_tools == new_enabled_tools_set:
                return 1

            new_tool_config = {}
            for tool_name in TOOL_REGISTRY.keys():
                tool_name_str = tool_name.value
                new_tool_config[tool_name_str] = tool_name_str in new_enabled_tools_set

            if save_tool_config(new_tool_config):
                CBController.exposed_tools = new_enabled_tools_set
            else:
                print("Failed to save tool configuration. Check IDA output log.")
        return 1

MAX_CONTEXT_FUNCTIONS = 50
class SelectBinaryFunctionsContext :
    def __init__(self) : pass

    @staticmethod
    def get_current_function_name(show_warning = False) :
        """Returns the current function information in the format function_name, function_address, flag. If flag is false, function_name and function_address are invalid; else carry on as per normal"""
        try :
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func :
                func_ea = next(idautils.Functions(), None)
                if func_ea is None :
                    if (show_warning) :
                        ida_kernwin.warning("No functions found in binary")
                        print("[AETHER Manual Context Setter] No functions found in binary.")
                    return -1 ,-1, False
                func_name = ida_funcs.get_func_name(func_ea)
                func_addr = hex(func_ea)
            else :
                func_name = ida_funcs.get_func_name(func.start_ea)
                func_addr = hex(func.start_ea)
        except Exception :
            if (show_warning) :
                ida_kernwin.warning("Unable to get current function address.")
                print("[AETHER Manual Context Setter] Unable to get current function address.")
            return -1, -1, False
        return func_name, func_addr, True

    @staticmethod
    def select_binary_functions_context(CBController) :
        """Prompts the user to manually select binary functions to add into manual context"""
        print("[AETHER Manual Context Setter] Manual selection of context in progress...")
        func_name, func_addr, flag = SelectBinaryFunctionsContext.get_current_function_name(show_warning = True)
        if (not flag) : return
        dlg = FunctionSelectionDialog(func_name, func_addr, "Manually select binary functions as Context", parent=CBController.parent, onlyTopLevel = True)
        if not dlg.exec_() : return

        CBController.manual_context = dlg.get_selected_functions()
        if (not CBController.manual_context) :
            ida_kernwin.warning("No functions selected.")
            print("[AETHER Manual Context Setter] No functions selected.")
            return
        if (len(CBController.manual_context) > MAX_CONTEXT_FUNCTIONS):
            ida_kernwin.warning(f"You selected {len(CBController.manual_context)} functions, but the limit is {MAX_CONTEXT_FUNCTIONS} to prevent exceeding the AI context window.\n\nTruncating to the first {MAX_CONTEXT_FUNCTIONS} functions.")
            print(f"[AETHER Manual Context Setter] Truncated selection from {len(CBController.manual_context)} to {MAX_CONTEXT_FUNCTIONS}.")
            CBController.manual_context = CBController.manual_context[:MAX_CONTEXT_FUNCTIONS]
        print(f"[AETHER Manual Context Setter] {len(CBController.manual_context)} functions selected for context.")
        CBController._refresh_context_pills()
        print(f"[AETHER Manual Context Setter] {len(CBController.manual_context)} selected functions for analysis.")

    @staticmethod
    def settle_manual_context(CBController) :
        if not CBController.manual_context:
            return ""

        header = (
            "========================================\n"
            "[SYSTEM DIRECTIVE: REQUIRED CONTEXT]\n"
            "The user has manually designated the following binary functions as critical context. "
            "You must prioritize analyzing these functions, retrieve their data if necessary, "
            "and actively integrate their behavior into your reasoning for the subsequent query:\n\n"
        )

        func_lines = [f"  - Target Function: '{f['name']}' at address [{f['address']}]" for f in CBController.manual_context]
        functions_str = "\n".join(func_lines)

        footer = (
            "\n\n[END REQUIRED CONTEXT]\n"
            "Ensure the functions listed above form the core basis of your upcoming response.\n"
            "========================================\n\n"
        )

        renamed_notice = (
            "You are to note that functions labelled with the prefix 'aire' are not original functions but rather renamed functions.\n"
            "Do not treat them as functions that came with the binary itself but rather analyses that you have performed.\n"
            "========================================\n\n"
        )

        return header + functions_str + footer + renamed_notice

class StopCurrentPrompt :
    def __init__(self) : pass

    @staticmethod
    def stop_current_prompt(CBController) :
        """Stops current prompt and breaks the thinking loop"""
        if (not CBController.is_thinking) : return
        CBController._request_force_stop()
        CBController._cleanup()
        CBController._add_message("SYSTEM", "Force Stop Complete")
        print("[AETHER Chatbot] Force stop complete. Ready for new user query.")
        CBController.is_thinking = False