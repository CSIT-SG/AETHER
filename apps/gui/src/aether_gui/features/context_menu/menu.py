import asyncio
from typing import cast

import ida_kernwin
from aether_gui.features.annotator import AnnotatorHandler
from aether_gui.features.chatbot import ChatbotHandler
from aether_gui.features.documentation import DocumentationHandler
from aether_gui.features.manage_struct import ManageStructHandler
from aether_gui.features.report_generator import GenerateReportHandler
from aether_gui.features.settings_menu import CtxSettingsMenuHandler
from aether_gui.features.unflatten_function import UnflattenHandler
from aether_gui.features.whats_new import WhatsNewHandler
from aether_gui.utils.mcp import MCPClient
from aether_utils.logger import get_logger

from .menu_item import ContextMenuItem

logger = get_logger("context_menu")


class DummyHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        return 0


class AetherUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self) -> None:
        super().__init__()

        self.mcp_client = MCPClient()

        manage_struct_operations = [
            ContextMenuItem(
                "aether:create_struct",
                "Create Struct",
                ManageStructHandler(self.mcp_client, "create"),
            ),
            ContextMenuItem(
                "aether:reevaluate_struct",
                "Re-evaluate Struct",
                ManageStructHandler(self.mcp_client, "update"),
            ),
        ]

        help_operations = [
            ContextMenuItem("aether:settings", "AETHER Settings", CtxSettingsMenuHandler()),
            ContextMenuItem("aether:whats_new", "What's New", WhatsNewHandler()),
        ]

        self.items = [
            ContextMenuItem("aether:chatbot", "Open AI Chatbot", ChatbotHandler(self.mcp_client)),
            ContextMenuItem(
                "aether:annotator", "Annotate Function", AnnotatorHandler(self.mcp_client)
            ),
            ContextMenuItem(
                "aether:manage_struct", "Manage Struct", children=manage_struct_operations
            ),
            ContextMenuItem(
                "aether:unflattner", "Unflatten Function", UnflattenHandler(self.mcp_client)
            ),
            ContextMenuItem(
                "aether:generate_report", "Generate Report", GenerateReportHandler(self.mcp_client)
            ),
            ContextMenuItem("aether:help", "Help", children=help_operations),
            ContextMenuItem("aether:documentation", "Documentation", DocumentationHandler()),
        ]

    def finish_populating_widget_popup(
        self,
        widget: object,
        popup_handle: object,
        *args: object,
        ctx: ida_kernwin.action_ctx_base_t | None = None,
        **kwargs: object,
    ) -> None:

        wtype = ida_kernwin.get_widget_type(widget)
        if ctx is None and args:
            ctx = cast(ida_kernwin.action_ctx_base_t, args[0])

        if wtype != ida_kernwin.BWN_PSEUDOCODE:
            return

        for item in self.items:
            try:
                item.register()

            except Exception as e:
                logger.error("Failed to register context menu item: %s", e)

            item.attach_to_popup(widget, popup_handle)

    def unregister(self) -> None:
        for item in self.items:
            try:
                item.unregister()

            except Exception as e:
                logger.warning("Failed to unregister context menu item: %s", e)

        self.items.clear()
        asyncio.run(self.mcp_client.close())
