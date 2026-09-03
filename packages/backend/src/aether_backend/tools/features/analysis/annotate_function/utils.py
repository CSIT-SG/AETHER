from collections.abc import Iterator

from aether_rpc.capabilities.function.types import FunctionTreeNode


def iter_addresses(node: FunctionTreeNode) -> Iterator[str]:
    yield node["address"]
    for child in node["children"]:
        yield from iter_addresses(child)
