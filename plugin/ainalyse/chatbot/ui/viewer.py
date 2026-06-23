import re

import ida_idaapi
import ida_kernwin
import ida_name
import idc

from ainalyse.qt_shim import QtCore, QtGui, QtWidgets, is_deleted

from ..controller import ChatbotController
from .context_menu import ChatbotContextMenu

CHATBOT_VIEW_TITLE = "AETHER Chatbot V2"


class ChatInputBox(QtWidgets.QTextEdit):
    returnPressed = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
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
                super().keyPressEvent(event)
            else:
                # Enter without Shift: Emit the send signal
                self.returnPressed.emit()
                event.accept()
        else:
            super().keyPressEvent(event)


class FlowLayout(QtWidgets.QLayout):
    """A custom layout that wraps items to the next line when space runs out.
    For context menu function selection
    """
    def __init__(self, parent=None, margin=0, spacing=-1):
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self.itemList = []

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
        super().setGeometry(rect)
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

    def _doLayout(self, rect, test_only):
        x = rect.x()
        y = rect.y()
        line_height = 0
        spacing = self.spacing()

        for item in self.itemList:
            space_x = spacing
            space_y = spacing
            next_x = x + item.sizeHint().width() + space_x

            # If the item hits the right edge, drop it to the next line
            if next_x - space_x > rect.right() and line_height > 0:
                x = rect.x()
                y = y + line_height + space_y
                next_x = x + item.sizeHint().width() + space_x
                line_height = 0

            if not test_only:
                item.setGeometry(QtCore.QRect(QtCore.QPoint(x, y), item.sizeHint()))

            x = next_x
            line_height = max(line_height, item.sizeHint().height())

        return y + line_height - rect.y()


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
                try:
                    if is_deleted(self.owner):
                        return False
                except Exception:
                    return False

                # If search bar is open, close it
                controller = getattr(self.owner, "controller", None)
                if controller and controller.search_bar is not None and controller.search_bar.isVisible():
                    controller._hide_search()
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

class ChatHistoryView(QtWidgets.QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._preserve_selection_on_focus_loss()

    def _preserve_selection_on_focus_loss(self):
        """Ensures the selection highlight remains bright even when IDA Pro takes active focus."""
        palette = self.palette()
        active_highlight = palette.color(QtGui.QPalette.Active, QtGui.QPalette.Highlight)
        active_text = palette.color(QtGui.QPalette.Active, QtGui.QPalette.HighlightedText)

        # Force the inactive state to use the same highly visible colors as the active state
        palette.setColor(QtGui.QPalette.Inactive, QtGui.QPalette.Highlight, active_highlight)
        palette.setColor(QtGui.QPalette.Inactive, QtGui.QPalette.HighlightedText, active_text)
        self.setPalette(palette)

    def mouseDoubleClickEvent(self, event):
        # Get cursor at the double-clicked position
        cursor = self.cursorForPosition(event.pos())
        position = cursor.position()
        block = cursor.block()
        block_text = block.text()
        relative_pos = position - block.position()

        # Match typical identifiers including names, hex addresses, Go dots, and C++ namespaces
        pattern = re.compile(r'[a-zA-Z0-9_\-.:]+')
        matches = list(pattern.finditer(block_text))

        target_identifier = None
        match_start = -1
        match_end = -1

        for m in matches:
            if m.start() <= relative_pos <= m.end():
                target_identifier = m.group(0)
                match_start = m.start()
                match_end = m.end()
                break

        if target_identifier:
            # Clean up trailing/leading punctuation often attached during natural language generation
            stripped_identifier = target_identifier.strip(".,;:!?()[]{}'`\"")

            if stripped_identifier:
                # Calculate character offsets stripped from the left and right edges
                left_strip = len(target_identifier) - len(target_identifier.lstrip(".,;:!?()[]{}'`\""))
                right_strip = len(target_identifier) - len(target_identifier.rstrip(".,;:!?()[]{}'`\""))

                # Determine the exact bounds of the stripped word relative to the document
                start_pos = block.position() + match_start + left_strip
                end_pos = block.position() + match_end - right_strip

                # Set the selection to highlight the exact word clicked
                highlight_cursor = self.textCursor()
                highlight_cursor.setPosition(start_pos)
                highlight_cursor.setPosition(end_pos, QtGui.QTextCursor.KeepAnchor)
                self.setTextCursor(highlight_cursor)

                self._jump_to_identifier(stripped_identifier)
                event.accept()
                return

        super().mouseDoubleClickEvent(event)

    def _jump_to_identifier(self, identifier):
        def do_jump():
            # Try to parse as hex or integer address
            try:
                if identifier.lower().startswith("0x"):
                    ea = int(identifier, 16)
                else:
                    ea = int(identifier)
                if ea != ida_idaapi.BADADDR:
                    ida_kernwin.jumpto(ea)
                    return True
            except ValueError:
                pass

            # Try to resolve as a named function or symbol
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, identifier)
            if ea != ida_idaapi.BADADDR:
                ida_kernwin.jumpto(ea)
                return True

            # Fallback name resolution
            ea = idc.get_name_ea_simple(identifier)
            if ea != ida_idaapi.BADADDR:
                ida_kernwin.jumpto(ea)
                return True

            return False

        # Marshal safely back to the main thread
        ida_kernwin.execute_sync(do_jump, ida_kernwin.MFF_READ)

# Global controller instance so chat history persists across window toggles
g_chatbot_controller = None

class ChatbotViewer(ida_kernwin.PluginForm):
    def __init__(self, dock_target="Pseudocode-A"):
        super().__init__()
        global g_chatbot_controller
        if g_chatbot_controller is None:
            g_chatbot_controller = ChatbotController()
        self.controller = g_chatbot_controller
        self.dock_target = dock_target
        self._esc_filter = None
        self._find_shortcut = None

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        self._init_ui(parent)

    def OnClose(self, form):
        # Stop current prompt generation but do not fully shutdown the global controller
        try:
            self.controller._stop_currrent_prompt()
        except Exception:
            pass

        # Disconnect signals to prevent PySide/PyQt proxy crashes when C++ widgets are destroyed later
        try:
            if self._find_shortcut is not None:
                self._find_shortcut.activated.blockSignals(True)
            if self.controller.search_bar is not None:
                self.controller.search_bar.blockSignals(True)
                self.controller.search_bar.search_input.blockSignals(True)
            if self.controller.history_view is not None:
                self.controller.history_view.blockSignals(True)
            if self.controller.context_gear_btn is not None:
                self.controller.context_gear_btn.blockSignals(True)
            if self.controller.input_box is not None:
                self.controller.input_box.blockSignals(True)
            if self.controller.pills_layout is not None:
                for i in range(self.controller.pills_layout.count()):
                    item = self.controller.pills_layout.itemAt(i)
                    if item and item.widget():
                        item.widget().blockSignals(True)
        except Exception:
            pass

        self._find_shortcut = None

        # Safer cleanup of global event filter
        try:
            app = QtWidgets.QApplication.instance()
            # We MUST remove the event filter if the app still exists,
            # otherwise IDA will crash when it next processes an event
            # and tries to call into our freed Python object.
            if app is not None and self.controller.theme_filter is not None:
                # Even if closingDown() is true, we should try to remove it
                # if the object is still registered.
                try:
                    app.removeEventFilter(self.controller.theme_filter)
                except Exception as e:
                    print(f"[DEBUG] Failed to remove theme filter: {e}")
        except Exception:
            pass
        finally:
            self.controller.theme_filter = None

        # Defensive event filter removal
        if self._esc_filter is not None:
            widgets_to_clean = [
                self.controller.main_widget,
                self.controller.history_view,
                self.controller.input_box,
            ]
            for widget in widgets_to_clean:
                if widget is not None:
                    try:
                        if not is_deleted(widget):
                            # Ensure the filter itself isn't deleted
                            if not is_deleted(self._esc_filter):
                                widget.removeEventFilter(self._esc_filter)
                    except Exception:
                        pass

            self._esc_filter = None

        try:
            self.controller.detach_ui()
        except Exception:
            pass

    def Show(self):
        res = super().Show(
            CHATBOT_VIEW_TITLE,
            options=(ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WCLS_CLOSE_LATER),
        )
        if res:
            ida_kernwin.set_dock_pos(CHATBOT_VIEW_TITLE, self.dock_target, ida_kernwin.DP_RIGHT)
        return res

    def _init_ui(self, parent):
        main_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(main_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        self._esc_filter = EscapeEventFilter(self)
        main_widget.installEventFilter(self._esc_filter)

        # Ctrl+F should only trigger when focus is within the chatbot widget tree.
        shortcut_cls = QtWidgets.QShortcut if hasattr(QtWidgets, "QShortcut") else QtGui.QShortcut
        self._find_shortcut = shortcut_cls(QtGui.QKeySequence.Find, main_widget)
        self._find_shortcut.setContext(QtCore.Qt.WidgetWithChildrenShortcut)
        self._find_shortcut.activated.connect(self.controller._show_search)

        search_bar = SearchBarWidget()
        search_bar.setVisible(False)
        search_bar.next_clicked.connect(lambda text: self.controller._do_search(text, forward=True, is_next_call=True))
        search_bar.prev_clicked.connect(lambda text: self.controller._do_search(text, forward=False, is_next_call=True))
        search_bar.close_clicked.connect(self.controller._hide_search)
        search_bar.search_input.textChanged.connect(self.controller._do_search)
        layout.addWidget(search_bar)

        history_view = ChatHistoryView()
        history_view.setReadOnly(True)
        history_view.document().setDocumentMargin(10)
        history_view.setAcceptRichText(True)
        history_view.setPlaceholderText("Welcome to the AETHER Chatbot V2...")
        history_view.setStyleSheet("font-size: 10pt;")
        history_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        history_view.customContextMenuRequested.connect(lambda pos: ChatbotContextMenu._show_context_menu(self.controller, pos))
        history_view.installEventFilter(self._esc_filter)
        layout.addWidget(history_view)

        context_frame = QtWidgets.QFrame()
        context_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        context_frame.setStyleSheet("background: #f5f5f5; border-radius: 8px; padding: 4px 8px;")
        context_frame.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        context_hbox = QtWidgets.QHBoxLayout(context_frame)
        context_hbox.setContentsMargins(4, 2, 4, 2)
        context_hbox.setSpacing(6)

        context_gear_btn = QtWidgets.QPushButton()
        context_gear_btn.setFixedSize(24, 24)
        context_gear_btn.setCursor(QtCore.Qt.PointingHandCursor)
        icon = QtGui.QIcon.fromTheme("mail-attachment")
        if icon.isNull():
            icon = QtGui.QIcon.fromTheme("preferences-desktop")

        if icon.isNull():
            context_gear_btn.setText("+")
            context_gear_btn.setStyleSheet("""
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
            context_gear_btn.setIcon(icon)
        context_gear_btn.setToolTip("Add context from binary functions")
        context_gear_btn.clicked.connect(self.controller._select_binary_functions_context)
        context_hbox.addWidget(context_gear_btn)

        pills_scroll = QtWidgets.QScrollArea()
        pills_scroll.setWidgetResizable(True)
        pills_scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        pills_scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        pills_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        pills_scroll.setStyleSheet("background: transparent;")
        pills_scroll.setFixedHeight(45)
        pills_scroll.verticalScrollBar().setStyleSheet("""
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

        pills_container = QtWidgets.QWidget()
        pills_container.setStyleSheet("background: transparent;")
        pills_layout = FlowLayout(pills_container, margin=0, spacing=6)
        pills_scroll.setWidget(pills_container)
        context_hbox.addWidget(pills_scroll)
        layout.addWidget(context_frame)

        input_box = ChatInputBox()
        input_box.installEventFilter(self._esc_filter)
        input_box.returnPressed.connect(self.controller.send_message)
        layout.addWidget(input_box)

        self.controller.bind_widgets(
            parent,
            main_widget,
            history_view,
            input_box,
            context_frame,
            context_gear_btn,
            pills_scroll,
            pills_container,
            pills_layout,
            search_bar,
        )

        self.controller._apply_theme_styles()
        self.controller._install_theme_refresh_hook()
        self.controller._refresh_context_pills()

        main_layout = QtWidgets.QVBoxLayout(parent)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(main_widget)

        for entry in self.controller.PERSISTENT_MESSAGE_LOG:
            self.controller._render_message(entry['sender'], entry['msg'])

def show_chatbot_viewer(dock_target="Pseudocode-A"):
    widget = ida_kernwin.find_widget(CHATBOT_VIEW_TITLE)
    if widget:
        ida_kernwin.activate_widget(widget, True)
    else:
        view = ChatbotViewer(dock_target=dock_target)
        view.Show()
