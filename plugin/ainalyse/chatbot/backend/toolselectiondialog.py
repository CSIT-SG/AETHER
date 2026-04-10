from PyQt5 import QtWidgets, QtCore

class ToolSelectionDialog(QtWidgets.QDialog):
    def __init__(self, current_active_tools: set, parent=None):
        super(ToolSelectionDialog, self).__init__(parent)
        self.setWindowTitle("AETHER Tool Exposure Configuration")
        self.setMinimumSize(400, 500)
        self.tool_checkboxes = {}
        self.active_tools = current_active_tools

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(QtWidgets.QLabel("Select which tools the AI agent should have access to:"))

        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        tools_container = QtWidgets.QWidget()
        tools_layout = QtWidgets.QVBoxLayout(tools_container)
        tools_layout.setAlignment(QtCore.Qt.AlignTop)

        from .tools import TOOL_REGISTRY
        for tool_name in TOOL_REGISTRY:
            checkbox = QtWidgets.QCheckBox(tool_name.value)
            checkbox.setChecked(tool_name.value in self.active_tools)
            self.tool_checkboxes[tool_name.value] = checkbox
            tools_layout.addWidget(checkbox)

        scroll_area.setWidget(tools_container)
        layout.addWidget(scroll_area)

        button_layout = QtWidgets.QHBoxLayout()
        select_all_btn = QtWidgets.QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all)
        deselect_all_btn = QtWidgets.QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(self.deselect_all)
        ok_btn = QtWidgets.QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QtWidgets.QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(select_all_btn)
        button_layout.addWidget(deselect_all_btn)
        button_layout.addStretch()
        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def select_all(self):
        for checkbox in self.tool_checkboxes.values():
            checkbox.setChecked(True)

    def deselect_all(self):
        for checkbox in self.tool_checkboxes.values():
            checkbox.setChecked(False)

    def get_selected_tools(self) -> set:
        return {name for name, checkbox in self.tool_checkboxes.items() if checkbox.isChecked()}

