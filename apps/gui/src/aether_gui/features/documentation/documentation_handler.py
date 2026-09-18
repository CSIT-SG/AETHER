import webbrowser
from typing import Any, Literal

import ida_kernwin
from aether_utils.get_version import get_version
from aether_utils.logger import get_logger

from .constants import DOC_LINK

logger = get_logger("whats_new_handler")


class DocumentationHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.version = get_version()

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        webbrowser.open(DOC_LINK)
        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
