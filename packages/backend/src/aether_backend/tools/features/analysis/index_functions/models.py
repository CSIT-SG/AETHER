from typing import NamedTuple, TypedDict

from aether_backend.utils.validation import HexAddress


class DecompileResult(NamedTuple):
    success: bool
    result: str  # either the pseudocode result or an error message


class FunctionClassification(TypedDict):
    name: str
    tags: list[str]
    summary: str
    key_operations: list[str]
    key_constants: list[str]
    called_apis: list[str]


class BlacklistEntry(TypedDict):
    name: str
    reason: str


class IndexResult(TypedDict):
    version: str
    sha256: str
    functions: dict[HexAddress, FunctionClassification]
    blacklist: dict[HexAddress, BlacklistEntry]
