from ainalyse.qt_shim import QtWidgets


class ChatbotContextMenu:
    def __init__(self) : pass

    @staticmethod
    def _show_context_menu(chatbot_controller, position):
        menu = QtWidgets.QMenu(chatbot_controller.parent)
        standard_menu = chatbot_controller.history_view.createStandardContextMenu()
        for action in standard_menu.actions():
            action.setParent(menu)
            menu.addAction(action)

        menu.addSeparator()

        menu.addAction("Find (Ctrl+F)", chatbot_controller._show_search)
        menu.addAction("Clear Chat History", chatbot_controller._refresh)
        menu.addAction("Manually Select Available Functions", chatbot_controller._select_exposed_tools)
        menu.addAction("Manually Select Binary Functions as Context", chatbot_controller._select_binary_functions_context)
        menu.addAction("Stop Prompt", chatbot_controller._stop_currrent_prompt)

        global_pos = chatbot_controller.history_view.viewport().mapToGlobal(position)
        menu.exec_(global_pos)
