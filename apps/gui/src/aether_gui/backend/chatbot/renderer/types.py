from datetime import datetime
from typing import Literal, Protocol

from aether_gui.features.chatbot.components.messages.Messages import MessageRole

type MessageType = Literal["tool", "text", "error"]


class ChatAreaProtocol(Protocol):
    def add_new_message_column(
        self, message: str, id: str, timestamp: datetime, role: MessageRole
    ) -> None: ...

    def add_paragraph_to_last_column(self, message: str, role: MessageRole) -> None: ...

    def append_to_last_paragraph_of_last_column(self, message: str) -> None: ...
