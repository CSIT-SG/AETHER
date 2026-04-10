from PyQt5 import QtGui, QtWidgets

class ChatbotContextMenu:
    def __init__(self) : pass

    @staticmethod
    def _show_context_menu(CBController, position):
        menu = QtWidgets.QMenu(CBController.parent)
        standard_menu = CBController.history_view.createStandardContextMenu()
        for action in standard_menu.actions():
            action.setParent(menu)
            menu.addAction(action)

        menu.addSeparator()

        menu.addAction("Find (Ctrl+F)", CBController._show_search)
        menu.addAction("Clear Chat History", CBController._refresh)
        menu.addAction("Manually Select Available Functions", CBController._select_exposed_tools)
        menu.addAction("Manually Select Binary Functions as Context", CBController._select_binary_functions_context)
        menu.addAction("Stop Prompt", CBController._stop_currrent_prompt)

        global_pos = CBController.history_view.viewport().mapToGlobal(position)
        menu.exec_(global_pos)