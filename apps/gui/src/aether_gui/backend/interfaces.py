from typing import Protocol

"""
Protocols are used for bottom to top dependencies to avoid circular imports
"""


class MessageProtocol(Protocol):
    def formatted_timestamp(self) -> str: ...


class ChatPanelProtocol(Protocol):
    def append_message(self, response: str) -> None: ...

    def add_message(self, response: str) -> None: ...
