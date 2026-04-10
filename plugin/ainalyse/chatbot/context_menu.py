from PyQt5 import QtWidgets

from ainalyse.chatbot.context_menu_items.select_exposed_tools import SelectExposedTools
from ainalyse.chatbot.context_menu_items.select_binary_functions_context import SelectBinaryFunctionsContext
from ainalyse.chatbot.context_menu_items.stop_current_prompt import StopCurrentPrompt
from ainalyse.chatbot.context_menu_items.clear_chat_history import ClearChatHistory

class ChatbotContextMenu() :
    def __init__(self) : pass

    @staticmethod
    def _show_context_menu(CBController, position) :
        menu = QtWidgets.QMenu(CBController.parent)
        standard_menu = CBController.history_view.createStandardContextMenu()
        for action in standard_menu.actions() :
            action.setParent(menu)
            menu.addAction(action)

        menu.addSeparator()

        menu.addAction("Clear Chat History", ClearChatHistory._clear_chat_history(CBController))
        menu.addAction("Manually Select Binary Functions as Context", SelectBinaryFunctionsContext._select_binary_functions_context(CBController))
        menu.addAction("Manually Select Available Functions", SelectExposedTools._select_exposed_tools(CBController))
        menu.addAction("Stop Prompt", StopCurrentPrompt._stop_current_prompt(CBController))

        global_pos = CBController.history_view.viewport().mapToGlobal(position)
        menu.exec_(global_pos)