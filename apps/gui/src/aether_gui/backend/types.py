from typing import Protocol

from aether_rpc.capabilities.types import AddressData, FunctionPseudocode


class IDAContext(AddressData, FunctionPseudocode):
    # Since both have name field with different typings, overwrite "name" type and ignore error
    name: str  # type: ignore


class ChatPanelProtocol(Protocol):
    def add_new_message_bubble(self, response: str) -> None: ...

    def append_to_last_message(self, response: str) -> None: ...
