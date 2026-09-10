from typing import Any, Literal

import ida_kernwin
from aether_utils.logger import get_logger

from .handler import SettingsMenuHandler

logger = get_logger("manage_struct_handler")


class CtxSettingsMenuHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:

        dialog = SettingsMenuHandler()
        dialog.exec()

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
