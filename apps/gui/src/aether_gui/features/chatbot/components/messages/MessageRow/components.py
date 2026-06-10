from PySide6.QtWidgets import QHBoxLayout, QWidget


class MessageRow(QWidget):
    def __init__(self, bubble, is_user, parent=None):
        super().__init__(parent)

        # Layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # User bubble aligned to right, Aether bubble aligned to left
        if is_user:
            layout.addStretch()
            layout.addWidget(bubble)
        else:
            layout.addWidget(bubble)
            layout.addStretch()
