from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from aether_gui.features.chatbot.components.messages.Messages import MessageRole
from aether_utils.logger import get_logger

from .types import ChatAreaProtocol, MessageType

logger = get_logger("ChatbotAreaRenderer")


class ChatbotAreaRenderer:
    def __init__(self, area: ChatAreaProtocol) -> None:
        self.area = area

    def render_aether_message(
        self, message: str, last_message_type: MessageType, *, message_created: bool
    ) -> None:

        if not message_created:
            self.area.add_new_message_row(message, str(uuid4()), datetime.now(), MessageRole.AETHER)
        elif last_message_type == "text":
            self.area.append_to_last_paragraph_of_last_row(message)
        else:
            self.area.add_paragraph_to_last_row(message, MessageRole.AETHER)

    def render_tool_message(self, message: str, *, message_created: bool) -> None:
        if not message_created:
            self.area.add_new_message_row(message, str(uuid4()), datetime.now(), MessageRole.AETHER)
        else:
            self.area.add_paragraph_to_last_row(message, MessageRole.AETHER)

    def render_error(self, message: str) -> None:
        self.area.add_new_message_row(
            f"Error: {message}", str(uuid4()), datetime.now(), MessageRole.AETHER
        )
