from __future__ import annotations

from aether_gui.features.settings_menu.styles import MESSAGE_STATE_PROPERTY, MessageState
from aether_utils.get_support import GatewaySupport
from PySide6 import QtWidgets

from .string_field import StringField


class ApiKeyField(StringField):
    """API-key field: a masked string field with a show/hide toggle and a ``Check``
    button that validates the key against the configured gateway.

    The check runs off the UI thread and reports the gateway's own result inline
    below the field. It validates the key currently typed here; the gateway URL,
    model and TLS settings come from the saved config.
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
    ) -> None:
        super().__init__(
            title,
            description,
            value,
            optional=optional,
            required=required,
            secret=True,
            placeholder=placeholder,
            example=example,
            parent=parent,
        )
        self._check_btn = self._make_field_button(
            "Check", "Validate this API key against the gateway", self._on_check
        )
        self.add_trailing_button(self._check_btn)

        self._status = QtWidgets.QLabel("", self)
        self._status.setWordWrap(True)
        self._status.hide()
        self._layout.addWidget(self._status)
        # Clear a stale result once the key is edited again.
        self._edit.textChanged.connect(lambda _: self._set_status("", MessageState.NONE))

    def _on_check(self) -> None:
        key = self.value() or ""
        if not key:
            self._set_status("Enter an API key first.", MessageState.ERROR)
            return
        # Lazy import: the worker lives higher in the settings package, so importing
        # it at module load would risk a settings_menu import cycle.
        from aether_gui.features.settings_menu.api_key_check import run_check

        self._check_btn.setEnabled(False)
        self._set_status("Checking…", MessageState.NONE)
        run_check(self._on_result, api_key=key)

    def _on_result(self, result: GatewaySupport) -> None:
        try:
            self._check_btn.setEnabled(True)
            state = MessageState.SUCCESS if result.supported else MessageState.ERROR
            self._set_status(result.detail, state)
        except RuntimeError:
            # The field was torn down (dialog closed or form rebuilt) before the
            # queued result arrived; nothing to update.
            pass

    def _set_status(self, text: str, state: MessageState) -> None:
        """Show the check result inline, coloured from the theme via ``messageState``."""
        self._status.setText(text)
        self._status.setProperty(MESSAGE_STATE_PROPERTY, state.value)
        self._status.setVisible(bool(text))
        style = self._status.style()
        style.unpolish(self._status)
        style.polish(self._status)
