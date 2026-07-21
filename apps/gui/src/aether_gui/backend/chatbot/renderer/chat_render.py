from __future__ import annotations

from aether_utils.logger import get_logger

from .types import ChatPanelProtocol, MessageType

logger = get_logger("ChatbotPanelRenderer")


class ChatbotPanelRenderer:
    def __init__(self, panel: ChatPanelProtocol) -> None:
        self.panel = panel

    def render_aether_message(
        self, message: str, last_message: MessageType, message_created: bool
    ) -> None:
        if not message_created:
            self.panel.add_new_message_bubble(message)
        elif last_message == "text":
            self.panel.append_to_last_paragraph(message)
        else:
            self.panel.add_new_paragraph(message)

    def render_tool_message(self, message: str, message_created: bool) -> None:
        if not message_created:
            self.panel.add_new_message_bubble(message + "\n")
        else:
            self.panel.add_new_paragraph(message + "\n")

    def render_error(self, message: str) -> None:
        self.panel.add_new_message_bubble(f"Error: {message}")
