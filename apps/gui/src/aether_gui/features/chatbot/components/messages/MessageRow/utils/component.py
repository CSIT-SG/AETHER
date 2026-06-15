from PySide6.QtWidgets import QPushButton

class ButtonComponent(QPushButton):
    def __init__(self, icon: str, obj_name: str, tooltip: str, parent=None):
        super().__init__(icon, parent)

        self.setObjectName(obj_name)
        self.setToolTip(tooltip)
