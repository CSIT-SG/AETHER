from dataclasses import dataclass

from aether_backend.utils.get_rpc_service import AnyService


@dataclass
class ToolDependencies:
    service: AnyService
