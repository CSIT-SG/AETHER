from .models import InternalToolRegistryEntry
from aether_backend.utils.rpc_discovery import RPCRegistry
from enum import StrEnum


class SubagentTool(StrEnum):
    ANNOTATOR = "annotator"
