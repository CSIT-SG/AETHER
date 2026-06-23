"""
Reusable dialogs for the chatbot UI.
"""
from ainalyse.qt_shim import QtWidgets
QMessageBox = QtWidgets.QMessageBox

import ida_kernwin

from ainalyse.indexing.function_index_manager import FunctionIndexManager
from ainalyse.indexing.function_indexer import FunctionIndexer


def prompt_for_indexing(parent=None):
    """
    Prompt the user to start or resume function indexing.

    Returns:
        bool: True if indexing is available or was started, False if declined.
    """
    idx = FunctionIndexManager.get_index()
    if idx.is_usable_for_queries():
        return True

    if FunctionIndexer.is_indexing_in_progress():
        QMessageBox.information(
            parent,
            "Indexing In Progress",
            "Indexing is already in progress. Please wait for it to complete and try again.",
        )
        return True

    can_resume = FunctionIndexManager.can_resume_indexing()
    if can_resume:
        message = (
            "The function index is incomplete for this binary. "
            "Would you like to resume indexing now?\n\n"
            "Note: This may take a few minutes depending on binary size."
        )
        title = "Resume Function Indexing"
    else:
        message = (
            "No usable function index exists for this binary. "
            "Would you like to start indexing now?\n\n"
            "Note: This may take a few minutes depending on binary size."
        )
        title = "Function Indexing Required"

    reply = QMessageBox.question(parent, title, message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply != QMessageBox.Yes:
        return False

    def on_success(index):
        def sync_info():
            ida_kernwin.info(f"Indexing complete: {index.size()} functions classified")
            return 1
        
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
             return

        ida_kernwin.execute_sync(
            sync_info,
            ida_kernwin.MFF_WRITE,
        )

    def on_failure(msg):
        def sync_warn():
            ida_kernwin.warning(f"Indexing failed: {msg}")
            return 1

        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
             return

        ida_kernwin.execute_sync(
            sync_warn,
            ida_kernwin.MFF_WRITE,
        )

    if can_resume:
        FunctionIndexer.resume_indexing(on_success, on_failure)
        QMessageBox.information(parent, "Indexing Started", "Resume indexing has started in the background.")
    else:
        FunctionIndexer.index_binary(on_success, on_failure)
        QMessageBox.information(parent, "Indexing Started", "Function indexing has started in the background.")
    return True
