
import ida_kernwin

from .controller import ChatbotController
from .context_menu import ChatbotContextMenu
from .core import AgentState
from PyQt5 import QtCore, QtGui, QtWidgets

# Constants
CHATBOT_VIEW_TITLE = "AETHER Chatbot"

class ChatbotView(ida_kernwin.PluginForm):
    def __init__(self, dock_target="Pseudocode-A") :
        super(ChatbotView, self).__init__()
        self.CBController = ChatbotController()
        self.dock_target = dock_target

    # parent method
    def OnCreate(self, form) :
        """Called when the form is created by IDA"""
        print("we're in oncreate now")
        self.CBController.parent = self.FormToPyQtWidget(form)
        self._init_ui()

    # parent method
    def OnClose(self, form) :
        """Called when the form is closed"""
        self.CBController.is_running = False

    # parent method
    def Show(self) :
        """Creates and shows the form."""
        res = super(ChatbotView, self).Show(
            CHATBOT_VIEW_TITLE,
            options=(ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WCLS_CLOSE_LATER)
        )
        if (res) :
            # Use the target title for docking (e.g., "Pseudocode-B")
            ida_kernwin.set_dock_pos(CHATBOT_VIEW_TITLE, self.dock_target, ida_kernwin.DP_RIGHT)
        return res

    def _init_ui(self) :
        """Initializes the UI components of the chatbot."""
        # Central widget to hold everything
        # self.CBController.main_widget = QtWidgets.QWidget()
        print("initting ui")
        layout = QtWidgets.QVBoxLayout(self.CBController.main_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # History View
        # self.CBController.history_view = QtWidgets.QTextEdit()
        self.CBController.history_view.setReadOnly(True)
        self.CBController.history_view.document().setDocumentMargin(10)
        # Enable HTML interaction for links or formatted code
        self.CBController.history_view.setAcceptRichText(True) 
        self.CBController.history_view.setPlaceholderText("Welcome to the AETHER Chatbot...")
        self.CBController.history_view.setStyleSheet("font-size: 10pt;")
        
        # Context Menu
        self.CBController.history_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        # self.CBController.history_view.customContextMenuRequested.connect(self._show_context_menu)
        self.CBController.history_view.customContextMenuRequested.connect(
            lambda pos : ChatbotContextMenu._show_context_menu(self.CBController, pos)
        )
        layout.addWidget(self.CBController.history_view)

        # self.CBController.context_frame = QtWidgets.QFrame()
        self.CBController.context_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.CBController.context_frame.setStyleSheet("background: #f5f5f5; border-radius: 8px; padding: 4px 8px;")
        context_hbox = QtWidgets.QHBoxLayout(self.CBController.context_frame)
        context_hbox.setContentsMargins(4, 2, 4, 2)
        context_hbox.setSpacing(6)

        # Paperclip button (was gear button)
        # self.CBController.context_gear_btn = QtWidgets.QPushButton()
        self.CBController.context_gear_btn.setFixedSize(24, 24)
        self.CBController.context_gear_btn.setCursor(QtCore.Qt.PointingHandCursor)
        icon = QtGui.QIcon.fromTheme("mail-attachment")
        if (icon.isNull()) :
            self.CBController.context_gear_btn.setText("📎")
            self.CBController.context_gear_btn.setStyleSheet("""
                QPushButton {
                    font-size: 12pt; 
                    color: #555;
                    border: none;
                    padding: 0px;
                    margin: 0px;
                    padding-bottom: 2px; 
                }
                QPushButton:hover {
                    color: #333;
                    background-color: #e0e0e0;
                    border-radius: 4px;
                }
            """)
        else : self.CBController.context_gear_btn.setIcon(icon)
        self.CBController.context_gear_btn.setToolTip("Add context from binary functions")
        self.CBController.context_gear_btn.clicked.connect(self.CBController._on_context_gear_clicked)
        context_hbox.addWidget(self.CBController.context_gear_btn)

        # Pills container
        # self.CBController.pills_container = QtWidgets.QWidget()
        # self.CBController.pills_layout = QtWidgets.QHBoxLayout(self.CBController.pills_container)
        self.CBController.pills_layout.setContentsMargins(0, 0, 0, 0)
        self.CBController.pills_layout.setSpacing(6)
        context_hbox.addWidget(self.CBController.pills_container)
        context_hbox.addStretch()

        layout.addWidget(self.CBController.context_frame)

        # Input Box
        # self.CBController.input_box = QtWidgets.QLineEdit()
        self.CBController.input_box.setPlaceholderText("Type your message here and press Enter...")
        self.CBController.input_box.returnPressed.connect(self.CBController.send_message)
        layout.addWidget(self.CBController.input_box)

        self.CBController._refresh_context_pills()

        # Attach to IDA's parent form
        # Secondary layout or direct parenting
        main_layout = QtWidgets.QVBoxLayout(self.CBController.parent)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.CBController.main_widget)
        
        for entry in self.CBController.PERSISTENT_MESSAGE_LOG:
            self._render_message(entry['sender'], entry['msg'])

def show_chatbot_view(dock_target="Pseudocode-A") :
    """
    Creates and shows a new instance of the chatbot viewer.
    Opens to the right of pseudocode view.
    """
    widget = ida_kernwin.find_widget(CHATBOT_VIEW_TITLE)
    if (widget) : ida_kernwin.activate_widget(widget, True)
    else :
        view = ChatbotView(dock_target=dock_target)
        view.Show()
        print("view has been made!")