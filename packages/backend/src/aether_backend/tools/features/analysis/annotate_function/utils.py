from collections.abc import Iterator
from typing import Any

from aether_backend.forwarded_rpc import get_functions_called_recursively
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import FunctionTreeNode, FunctionTreeResult


async def manually_gather(service: Any, address: HexAddress) -> FunctionTreeResult:
    call_tree = await get_functions_called_recursively(service, address=address)
    if not isinstance(call_tree.result, str):
        return call_tree.result
    raise RuntimeError(call_tree.result)


def iter_addresses(node: FunctionTreeNode) -> Iterator[str]:
    yield node["address"]
    for child in node["children"]:
        yield from iter_addresses(child)
