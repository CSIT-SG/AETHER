from __future__ import annotations

from aether_utils.logger import get_logger

from ..types import ChatPanelProtocol
from .types import MessageType

logger = get_logger("ChatbotPanelRenderer")


class ChatbotPanelRenderer:
    def __init__(self, panel: ChatPanelProtocol) -> None:
        self.panel = panel
        self.last_message: MessageType | None = None

    def render_aether_message(self, message: str) -> None:
        if self.last_message == "text":
            self.panel.append_to_last_message(message)
        else:
            self.panel.add_new_message_bubble(message)
            self.last_message = "text"

    def render_tool_message(self, message: str) -> None:
        self.panel.add_new_message_bubble(message + "\n")
        self.last_message = "tool"

    def render_tool_output(self, message: str) -> None:
        if self.last_message == "tool":
            self.panel.append_to_last_message(message)
        else:
            self.panel.add_new_message_bubble(message + "\n")
            self.last_message = "tool"

    def render_error(self, message: str) -> None:
        if self.last_message == "error":
            self.panel.append_to_last_message(f"Error: {message}")
        else:
            self.panel.add_new_message_bubble(f"Error: {message}")
            self.last_message = "text"
