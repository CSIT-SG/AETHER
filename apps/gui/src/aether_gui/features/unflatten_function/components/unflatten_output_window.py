from typing import cast

import ida_kernwin
from aether_gui.utils.constants import WINDOW_PREFIX
from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6 import QtWidgets
from PySide6.QtGui import QFont


class UnflattenOutputWidget(StyledComponent):
    """container for text,"""

    def __init__(
        self,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        self._text = UnflattenOutputText()
        super().__init__(parent)
        self._text.set_text("Loading...")

    def init_ui(self) -> None:
        layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.addWidget(self._text)

    def set_text(self, text: str) -> None:
        """Thread-safe. Call from anywhere, including a worker thread."""
        if self._text is not None:
            self._text.set_text(text)


class UnflattenOutputText(StyledComponent):
    """Text box"""

    def __init__(
        self,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        # Set before super().__init__() since StyledComponent calls init_ui()
        # during its own construction, before the first style pass.
        super().__init__(parent, plugins=[FontPlugin()])

    def init_ui(self) -> None:
        layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._text = QtWidgets.QTextBrowser(self)
        self._text.setReadOnly(True)
        layout.addWidget(self._text)

    def on_font_change(self, font: QFont) -> None:
        """Keep the text widget's own QFont in sync with the shared FontManager.

        Args:
            font: The newly active font.
        """
        if self._text is not None:
            self._text.setFont(font)

    def _current_font(self) -> QFont:
        """Return the current font.

        Returns:
            The active font, falling back to the shared manager
            if the font plugin is unavailable.
        """
        return cast(QFont, self.get_plugin(FontPlugin).current_font)

    def set_text(self, text: str) -> None:
        """Thread-safe. Call from anywhere, including a worker thread."""
        print(text)

        def _apply() -> int:
            if self._text is not None:
                self._text.setMarkdown(text)
            return 1

        ida_kernwin.execute_sync(_apply, ida_kernwin.MFF_FAST)


class UnflattenOutputWindow(ida_kernwin.PluginForm):
    """Window in IDA"""

    def __init__(
        self,
        title: str = f"{WINDOW_PREFIX} Unflatten Function",
    ) -> None:
        super().__init__()
        self._title: str = title
        self._widget: UnflattenOutputWidget | None = None

    def OnCreate(self, form: int) -> None:
        parent: QtWidgets.QWidget = cast(QtWidgets.QWidget, self.FormToPyQtWidget(form))

        self._widget = UnflattenOutputWidget(parent)

        layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(1, 1, 1, 1)
        layout.addWidget(self._widget)
        parent.setLayout(layout)

    def OnClose(self, form: int) -> None:
        self._widget = None

    def show(self) -> None:
        self.Show(
            self._title,
            options=ida_kernwin.PluginForm.WOPN_PERSIST,
        )

    def set_text(self, text: str) -> None:
        """Thread-safe. Call from anywhere, including a worker thread."""
        if self._widget is not None:
            self._widget.set_text(text)
