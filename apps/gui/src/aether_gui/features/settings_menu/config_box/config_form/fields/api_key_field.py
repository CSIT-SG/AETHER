from __future__ import annotations

from aether_gui.features.settings_menu.styles import MESSAGE_STATE_PROPERTY, MessageState
from aether_utils.provider_check import CheckResult, CheckTask
from PySide6 import QtWidgets

from .secret_field import SecretField


class ApiKeyField(SecretField):
    """Masked API-key field with a ``Check`` button that runs an injected validation
    ``task`` and shows the result inline below the field.

    The task is injected (dependency inversion) so the field depends only on the
    :data:`CheckTask` contract, not on the gateway/OpenAI probe: it stays swappable
    for other providers/conventions and trivial to fake in tests. A task receives the
    typed value and a callback, runs off the UI thread, and delivers a
    :class:`CheckResult` to the callback on the UI thread.
    """

    def __init__(
        self,
        title: str,
        description: str,
        value: object,
        *,
        optional: bool,
        required: bool = False,
        placeholder: str = "",
        example: str = "",
        parent: QtWidgets.QWidget | None = None,
        task: CheckTask,
    ) -> None:
        super().__init__(
            title,
            description,
            value,
            optional=optional,
            required=required,
            placeholder=placeholder,
            example=example,
            parent=parent,
        )
        self._task = task
        self._check_btn = self._make_button("Check", "Validate this API key", self._on_check)
        self._row_layout.addWidget(self._check_btn)

        self._status = QtWidgets.QLabel("", self)
        self._status.setWordWrap(True)
        self._status.hide()
        self._layout.addWidget(self._status)
        self._edit.textChanged.connect(lambda _: self._set_status("", MessageState.NONE))

    def _on_check(self) -> None:
        key = self.value() or ""
        if not key:
            self._set_status("Enter an API key first.", MessageState.ERROR)
            return
        # Return focus to the field before disabling: disabling a focused button makes
        # Qt advance focus to the next field.
        self._edit.setFocus()
        self._check_btn.setEnabled(False)
        self._set_status("Checking…", MessageState.NONE)
        self._task(key, self._on_result)

    def _on_result(self, result: CheckResult) -> None:
        try:
            self._check_btn.setEnabled(True)
            state = MessageState.SUCCESS if result.verdict else MessageState.ERROR
            self._set_status(result.detail, state)
        except RuntimeError:
            pass

    def _set_status(self, text: str, state: MessageState) -> None:
        """Show the check result inline, coloured from the theme via ``messageState``."""
        self._status.setText(text)
        self._status.setProperty(MESSAGE_STATE_PROPERTY, state.value)
        self._status.setVisible(bool(text))
        style = self._status.style()
        style.unpolish(self._status)
        style.polish(self._status)
