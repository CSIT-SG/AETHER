from dataclasses import dataclass
from typing import Any

from ..tags import SubagentToolRegistry

registry = SubagentToolRegistry()


@dataclass
class ToolDependencies:
    service: Any
