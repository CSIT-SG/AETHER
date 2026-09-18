from collections.abc import Callable
from typing import Any, Protocol


# we do not know the service signature at interpret time,
# so we loosely type it as a protocol that allows any attribute access and callable signature
class AnyService(Protocol):
    def __getattr__(self, name: str) -> Callable[..., Any]: ...
