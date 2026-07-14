from __future__ import annotations

from aether_utils.logger import get_logger

from ..types import ChatPanelProtocol

logger = get_logger("ChatbotPanelRenderer")


class ChatbotPanelRenderer:
    def __init__(self, panel: ChatPanelProtocol) -> None:
        self.panel = panel

    def render_aether_message(self, message: str) -> None:
        self.panel.append_to_last_message(message)

    def render_tool_message(self, message: str) -> None:
        self.panel.append_to_last_message("\n" + message + "\n")

    def render_status(self, message: str) -> None:
        self.panel.add_new_message_bubble(f"[status] {message}" + "\n")

    def render_error(self, message: str) -> None:
        self.panel.add_new_message_bubble(f"Error: {message}" + "\n")
