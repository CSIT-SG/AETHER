from PySide6 import QtCore, QtWidgets


class ScrollBar(QtWidgets.QScrollBar):
    """
    A dedicated scrollbar class allowing for isolated style
    and custom scroll behavior handling.
    """
    def __init__(self, orientation: QtCore.Qt.Orientation = QtCore.Qt.Orientation.Vertical, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(orientation, parent)
        self.apply_theme()

    def apply_theme(self) -> None:
        # TO BE DONE: Make the stylesheet get fetched from the stylesheets folder and not hardcoded here
        """Applies a clean, modern dark theme to the scrollbar."""
        self.setStyleSheet("""
            QScrollBar:vertical {
                border: none;
                background: #2d2d2d;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #555555;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #007acc;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
        """)