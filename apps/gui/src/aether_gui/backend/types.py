from typing import Protocol


class ChatPanelProtocol(Protocol):
    def add_new_message_bubble(self, response: str) -> None: ...

    def append_to_last_message(self, response: str) -> None: ...
