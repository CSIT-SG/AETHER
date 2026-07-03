from collections.abc import Callable

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets

from .button_create import ApplyButton, CancelButton, OkButton


class ButtonRow(StyledComponent):
    def __init__(
        self,
        get_content: Callable[[], str],
        on_close: Callable,
        on_error: Callable[[], None],
        clear_message_box: Callable[[], None],
        on_success: Callable[[], None],
        parent=None,
    ) -> None:
        self._get_content = get_content
        self._on_close = on_close
        self._on_error = on_error
        self._clear_message_box = clear_message_box
        self._on_success = on_success
        super().__init__(parent)

    def setup(self) -> None:
        self._layout: QtWidgets.QHBoxLayout
        self._ok: OkButton
        self._apply: ApplyButton
        self._cancel: CancelButton

    def init_ui(self) -> None:
        layout = QtWidgets.QHBoxLayout(self)
        layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight)
        layout.setContentsMargins(0, 0, 0, 0)
        self._layout = layout
        self.set_buttons(
            self._get_content,
            self._on_close,
            self._on_error,
            self._clear_message_box,
            self._on_success,
        )
        self.setLayout(self._layout)

    def set_buttons(
        self,
        get_content: Callable,
        on_close: Callable,
        on_error: Callable[[], None],
        clear_message_box: Callable[[], None],
        on_success: Callable[[], None],
    ) -> None:
        ok = OkButton(get_content, on_close, on_error, clear_message_box)
        apply = ApplyButton(get_content, on_error, clear_message_box, on_success)
        cancel: CancelButton = CancelButton(on_close)
        for btn in (ok, apply, cancel):
            btn.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed
            )
        self._apply = apply
        self._layout.addWidget(ok)
        self._layout.addWidget(apply)
        self._layout.addWidget(cancel)

    @property
    def apply_button(self) -> ApplyButton:
        return self._apply


def create_button_row(
    get_content: Callable[[], str],
    on_close: Callable,
    on_error: Callable[[], None],
    clear_message_box: Callable[[], None],
    on_success: Callable[[], None],
    parent: QtWidgets.QWidget | None = None,
) -> ButtonRow:
    return ButtonRow(get_content, on_close, on_error, clear_message_box, on_success, parent=parent)
