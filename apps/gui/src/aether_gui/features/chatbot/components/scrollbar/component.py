from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets


class ScrollBar(StyledComponent):
    """Themed scrollbar wrapper that can bind to a scroll area."""

    def __init__(
        self,
        orientation: QtCore.Qt.Orientation = QtCore.Qt.Orientation.Vertical,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        """Configure orientation and set up sync state."""
        self._orientation = orientation
        self._scrollbar: QtWidgets.QScrollBar | None = None
        self._target_scrollbar: QtWidgets.QScrollBar | None = None
        self._syncing = False
        super().__init__(parent)

    def init_ui(self) -> None:
        """Build the scrollbar widget and apply size constraints."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        scrollbar = QtWidgets.QScrollBar(self._orientation, self)
        scrollbar.setObjectName("ScrollBarHandle")
        scrollbar.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        layout.addWidget(scrollbar)
        self._scrollbar = scrollbar

        if self._orientation == QtCore.Qt.Orientation.Vertical:
            # Match the styled width for the vertical rail.
            self.setFixedWidth(10)
            self.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Fixed,
                QtWidgets.QSizePolicy.Policy.Expanding,
            )
        else:
            # Match the styled height for the horizontal rail.
            self.setFixedHeight(10)
            self.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Fixed,
            )

    def scrollbar(self) -> QtWidgets.QScrollBar:
        """Return the underlying Qt scrollbar widget."""
        if self._scrollbar is None:
            raise RuntimeError("ScrollBar not initialized")
        return self._scrollbar

    def bind_to(self, target: QtWidgets.QAbstractScrollArea | QtWidgets.QScrollBar) -> None:
        """Sync this component to a scroll area or scrollbar."""
        if isinstance(target, QtWidgets.QAbstractScrollArea):
            target_scrollbar = (
                target.verticalScrollBar()
                if self._orientation == QtCore.Qt.Orientation.Vertical
                else target.horizontalScrollBar()
            )
        else:
            target_scrollbar = target

        self._target_scrollbar = target_scrollbar
        self._sync_range(target_scrollbar.minimum(), target_scrollbar.maximum())
        self.scrollbar().setValue(target_scrollbar.value())

        target_scrollbar.valueChanged.connect(self._sync_from_target)
        target_scrollbar.rangeChanged.connect(self._sync_range)
        self.scrollbar().valueChanged.connect(self._sync_from_custom)

    def _sync_range(self, minimum: int, maximum: int) -> None:
        """Mirror target range and step sizes."""
        if self._target_scrollbar is None:
            return
        custom_scrollbar = self.scrollbar()
        custom_scrollbar.setRange(minimum, maximum)
        custom_scrollbar.setPageStep(self._target_scrollbar.pageStep())
        custom_scrollbar.setSingleStep(self._target_scrollbar.singleStep())

    def _sync_from_target(self, value: int) -> None:
        """Push target scroll values into the themed scrollbar."""
        if self._syncing:
            return
        self._syncing = True
        self.scrollbar().setValue(value)
        self._syncing = False

    def _sync_from_custom(self, value: int) -> None:
        """Push themed scrollbar values into the target."""
        if self._target_scrollbar is None or self._syncing:
            return
        self._syncing = True
        self._target_scrollbar.setValue(value)
        self._syncing = False

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the scrollbar."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"
