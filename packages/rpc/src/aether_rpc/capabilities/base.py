import logging
from abc import ABC, abstractmethod
from typing import Any, cast

from aether_utils.logger import get_logger


class Capability(ABC):
    @property
    def logger(self) -> logging.Logger:
        return cast(logging.Logger, get_logger(f"rpc.{self.name}"))

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def execute(self, *args: Any, **kwargs: Any) -> Any:
        pass
