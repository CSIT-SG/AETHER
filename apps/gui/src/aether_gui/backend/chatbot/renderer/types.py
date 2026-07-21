from typing import Literal, Protocol

type MessageType = Literal["tool", "text", "error"]


class ChatPanelProtocol(Protocol):
    def add_new_message_bubble(self, response: str) -> None: ...

    def add_new_paragraph(self, response: str) -> None: ...

    def append_to_last_paragraph(self, response: str) -> None: ...
