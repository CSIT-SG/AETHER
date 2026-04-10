import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets

from .context_menu import ChatbotContextMenu
from ..controller import ChatbotController

CHATBOT_VIEW_TITLE = "AETHER Chatbot"


class ChatInputBox(QtWidgets.QTextEdit):
    returnPressed = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(ChatInputBox, self).__init__(parent)
        self.setPlaceholderText("Type your message here... (Shift+Enter for new line)")
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        
        # Connect text changes to the resize function
        self.textChanged.connect(self.adjust_height)
        self.document().documentLayout().documentSizeChanged.connect(self.adjust_height)
        
        # Set constraints
        self.min_height = 30
        self.max_height = 150
        self.setFixedHeight(self.min_height)

    def adjust_height(self):
        """Dynamically adjust height based on document content."""
        doc_height = int(self.document().size().height())
        margins = self.contentsMargins()
        needed_height = doc_height + margins.top() + margins.bottom() + 5
        
        if needed_height > self.max_height:
            self.setFixedHeight(self.max_height)
            self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        else:
            self.setFixedHeight(max(self.min_height, needed_height))
            self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

    def keyPressEvent(self, event):
        """Handle Enter to send, Shift+Enter to break line."""
        if event.key() == QtCore.Qt.Key_Return or event.key() == QtCore.Qt.Key_Enter:
            if event.modifiers() & QtCore.Qt.ShiftModifier:
                # Normal Shift+Enter behavior (new line)
                super(ChatInputBox, self).keyPressEvent(event)
            else:
                # Enter without Shift: Emit the send signal
                self.returnPressed.emit()
                event.accept()
        else:
            super(ChatInputBox, self).keyPressEvent(event)


class FlowLayout(QtWidgets.QLayout):
    """A custom layout that wraps items to the next line when space runs out.
    For context menu function selection
    """
    def __init__(self, parent=None, margin=0, spacing=-1):
        super(FlowLayout, self).__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self.itemList = []

    def __del__(self):
        item = self.takeAt(0)
        while item:
            item = self.takeAt(0)

    def addItem(self, item):
        self.itemList.append(item)

    def count(self):
        return len(self.itemList)

    def itemAt(self, index):
        if index >= 0 and index < len(self.itemList):
            return self.itemList[index]
        return None

    def takeAt(self, index):
        if index >= 0 and index < len(self.itemList):
            return self.itemList.pop(index)
        return None

    def expandingDirections(self):
        return QtCore.Qt.Orientations(QtCore.Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        height = self._doLayout(QtCore.QRect(0, 0, width, 0), True)
        return height

    def setGeometry(self, rect):
        super(FlowLayout, self).setGeometry(rect)
        self._doLayout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QtCore.QSize()
        for item in self.itemList:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QtCore.QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def _doLayout(self, rect, testOnly):
        x = rect.x()
        y = rect.y()
        lineHeight = 0
        spacing = self.spacing()

        for item in self.itemList:
            spaceX = spacing
            spaceY = spacing
            nextX = x + item.sizeHint().width() + spaceX
            
            # If the item hits the right edge, drop it to the next line
            if nextX - spaceX > rect.right() and lineHeight > 0:
                x = rect.x()
                y = y + lineHeight + spaceY
                nextX = x + item.sizeHint().width() + spaceX
                lineHeight = 0

            if not testOnly:
                item.setGeometry(QtCore.QRect(QtCore.QPoint(x, y), item.sizeHint()))

            x = nextX
            lineHeight = max(lineHeight, item.sizeHint().height())

        return y + lineHeight - rect.y()


class SearchBarWidget(QtWidgets.QFrame):
    """A floating-style search bar for the history view."""
    next_clicked = QtCore.pyqtSignal(str)
    prev_clicked = QtCore.pyqtSignal(str)
    close_clicked = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Find...")
        self.search_input.installEventFilter(self) # For Enter/Shift+Enter

        # Counter label
        self.counter_label = QtWidgets.QLabel("0/0")
        self.counter_label.setStyleSheet("font-size: 9pt; border: none;")
        
        self.close_btn = QtWidgets.QPushButton("✕")
        self.close_btn.setFixedSize(20, 20)
        self.close_btn.setStyleSheet("border: none; color: #888; font-weight: bold;")
        self.close_btn.clicked.connect(self.close_clicked)

        layout.addWidget(self.search_input)
        layout.addWidget(self.counter_label)
        layout.addWidget(self.close_btn)

        palette = self.palette()
        self.apply_theme_styles(
            window_color=palette.color(QtGui.QPalette.Window).name(),
            base_color=palette.color(QtGui.QPalette.Base).name(),
            text_color=palette.color(QtGui.QPalette.Text).name(),
            mid_color=palette.color(QtGui.QPalette.Mid).name(),
        )

    def apply_theme_styles(self, window_color: str, base_color: str, text_color: str, mid_color: str):
        self.setStyleSheet(f"""
            SearchBarWidget {{
                background: {window_color};
                border: 1px solid {mid_color};
                border-radius: 4px;
            }}
            QLineEdit {{
                background: {base_color};
                color: {text_color};
                border: none;
                padding: 2px;
            }}
            QLabel {{
                color: {text_color};
            }}
            QPushButton {{
                border: none;
                color: {text_color};
                font-weight: bold;
            }}
        """)
    
    def update_counter(self, current, total):
        self.counter_label.setText(f"{current}/{total}" if total > 0 else "0/0")

    def eventFilter(self, obj, event):
        if obj is self.search_input and event.type() == QtCore.QEvent.KeyPress:
            if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if event.modifiers() & QtCore.Qt.ShiftModifier:
                    self.prev_clicked.emit(self.search_input.text())
                else:
                    self.next_clicked.emit(self.search_input.text())
                return True
        return super().eventFilter(obj, event)

    def setFocus(self):
        self.search_input.setFocus()

class EscapeEventFilter(QtCore.QObject):
    """A cross-compatible event filter to trap the Escape key."""
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress:
            # Handle Escape key
            if event.key() == QtCore.Qt.Key_Escape:
                # If search bar is open, close it
                if hasattr(self.owner, 'search_bar') and self.owner.search_bar.isVisible():
                    self.owner._hide_search()
                else:
                    print("[AETHER] Escape key suppressed.")
                return True # Consume the event
        return False
    
class ThemeRefreshEventFilter(QtCore.QObject):
    """Watches for global style/palette changes and triggers a refresh callback."""
    def __init__(self, refresh_callback):
        super().__init__()
        self.refresh_callback = refresh_callback

    def eventFilter(self, obj, event):
        if event.type() in (
            QtCore.QEvent.ApplicationPaletteChange,
            QtCore.QEvent.PaletteChange,
            QtCore.QEvent.StyleChange,
        ):
            self.refresh_callback()
        return False

class ChatbotViewer(ida_kernwin.PluginForm):
    def __init__(self, dock_target="Pseudocode-A"):
        super(ChatbotViewer, self).__init__()
        self.controller = ChatbotController()
        self.dock_target = dock_target

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        self._init_ui(parent)

    def OnClose(self, form):
        app = QtWidgets.QApplication.instance()
        if app is not None and self.controller.theme_filter is not None:
            app.removeEventFilter(self.controller.theme_filter)
            self.controller.theme_filter = None
        self.controller.is_running = False

    def Show(self):
        res = super(ChatbotViewer, self).Show(
            CHATBOT_VIEW_TITLE,
            options=(ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WCLS_CLOSE_LATER),
        )
        if res:
            ida_kernwin.set_dock_pos(CHATBOT_VIEW_TITLE, self.dock_target, ida_kernwin.DP_RIGHT)
        return res

    def _init_ui(self, parent):
        self.controller.parent = parent

        self.controller.main_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(self.controller.main_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        esc_filter = EscapeEventFilter(self)
        self.controller.main_widget.installEventFilter(esc_filter)

        self.controller.search_bar = SearchBarWidget()
        self.controller.search_bar.setVisible(False)
        self.controller.search_bar.next_clicked.connect(lambda text: self.controller._do_search(text, forward=True, is_next_call=True))
        self.controller.search_bar.prev_clicked.connect(lambda text: self.controller._do_search(text, forward=False, is_next_call=True))
        self.controller.search_bar.close_clicked.connect(self.controller._hide_search)
        self.controller.search_bar.search_input.textChanged.connect(self.controller._do_search)
        layout.addWidget(self.controller.search_bar)

        self.controller.history_view = QtWidgets.QTextEdit()
        self.controller.history_view.setReadOnly(True)
        self.controller.history_view.document().setDocumentMargin(10)
        self.controller.history_view.setAcceptRichText(True)
        self.controller.history_view.setPlaceholderText("Welcome to the AETHER Chatbot...")
        self.controller.history_view.setStyleSheet("font-size: 10pt;")
        self.controller.history_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.controller.history_view.customContextMenuRequested.connect(lambda pos: ChatbotContextMenu._show_context_menu(self.controller, pos))
        self.controller.history_view.installEventFilter(esc_filter)
        layout.addWidget(self.controller.history_view)

        self.controller.context_frame = QtWidgets.QFrame()
        self.controller.context_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        # self.controller.context_frame.setStyleSheet("background: #f5f5f5; border-radius: 8px; padding: 4px 8px;")
        self.controller.context_frame.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        context_hbox = QtWidgets.QHBoxLayout(self.controller.context_frame)
        context_hbox.setContentsMargins(4, 2, 4, 2)
        context_hbox.setSpacing(6)

        self.controller.context_gear_btn = QtWidgets.QPushButton()
        self.controller.context_gear_btn.setFixedSize(24, 24)
        self.controller.context_gear_btn.setCursor(QtCore.Qt.PointingHandCursor)
        icon = QtGui.QIcon.fromTheme("mail-attachment")
        if icon.isNull():
            icon = QtGui.QIcon.fromTheme("preferences-desktop")
        
        if icon.isNull():
            self.controller.context_gear_btn.setText("+")
            self.controller.context_gear_btn.setStyleSheet("""
                QPushButton {
                    font-size: 16pt;
                    font-weight: bold;
                    border: none;
                    padding: -2px 0px 2px 0px;
                    margin: 0px;
                    height: 28px;
                    width: 28px;
                    min-height: 28px;
                    min-width: 28px;
                    line-height: 28px;
                    text-align: center;
                }
            """)
        else:
            self.controller.context_gear_btn.setIcon(icon)
        self.controller.context_gear_btn.setToolTip("Add context from binary functions")
        self.controller.context_gear_btn.clicked.connect(self.controller._select_binary_functions_context)
        context_hbox.addWidget(self.controller.context_gear_btn)


        self.controller.pills_scroll = QtWidgets.QScrollArea()
        self.controller.pills_scroll.setWidgetResizable(True)
        self.controller.pills_scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.controller.pills_scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.controller.pills_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.controller.pills_scroll.setStyleSheet("background: transparent;")
        self.controller.pills_scroll.setFixedHeight(45) 
        self.controller.pills_scroll.verticalScrollBar().setStyleSheet("""
            QScrollBar:vertical {
                border: none;
                background: #e0e0e0;
                width: 8px; /* Forces it to be thin */
                border-radius: 4px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #a0a0a0;
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #707070;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
                background: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """)

        self.controller.pills_container = QtWidgets.QWidget()
        self.controller.pills_container.setStyleSheet("background: transparent;")
        self.controller.pills_layout = FlowLayout(self.controller.pills_container, margin=0, spacing=6)
        self.controller.pills_scroll.setWidget(self.controller.pills_container)
        context_hbox.addWidget(self.controller.pills_scroll)
        layout.addWidget(self.controller.context_frame)

        self.controller.input_box = ChatInputBox()
        self.controller.input_box.installEventFilter(esc_filter)
        self.controller.input_box.returnPressed.connect(self.controller.send_message)
        layout.addWidget(self.controller.input_box)
        self.controller._apply_theme_styles()
        self.controller._install_theme_refresh_hook()

        # context_gear_btn.clicked.connect(self.controller._select_binary_functions_context)

        self.controller._refresh_context_pills()

        # self.controller.bind_widgets(
        #     parent,
        #     main_widget,
        #     history_view,
        #     input_box,
        #     context_frame,
        #     context_gear_btn,
        #     self.controller.pills_scroll,
        #     pills_container,
        #     self.controller.pills_layout,
        #     search_bar,
        # )

        main_layout = QtWidgets.QVBoxLayout(parent)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.controller.main_widget)

        for entry in self.controller.PERSISTENT_MESSAGE_LOG:
            self.controller._render_message(entry['sender'], entry['msg'])

def show_chatbot_viewer(dock_target="Pseudocode-A"):
    widget = ida_kernwin.find_widget(CHATBOT_VIEW_TITLE)
    if widget:
        ida_kernwin.activate_widget(widget, True)
    else:
        view = ChatbotViewer(dock_target=dock_target)
        view.Show()