from collections.abc import Sequence

from ..services import ToolCommand
from ..services.tools import HelloWorld
from .base import AbstractMCPRoute


class HelloWorldRoute(AbstractMCPRoute):
    @property
    def prefix(self) -> str:
        return "printer"

    @property
    def tools(self) -> Sequence[ToolCommand]:
        return [
            ToolCommand(HelloWorld().to_tool(), HelloWorld().run),
        ]
