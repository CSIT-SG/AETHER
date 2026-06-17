from PySide6 import QtWidgets


def capture_original_stylesheet(widget: QtWidgets.QWidget) -> None:
    """Save the window's current stylesheet so it can be restored later."""
    window = widget.window()
    if window.property("_original_stylesheet") is None:
        window.setProperty("_original_stylesheet", window.styleSheet())
