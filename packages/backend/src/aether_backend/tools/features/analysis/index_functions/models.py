from enum import StrEnum
from typing import NamedTuple, TypedDict

from aether_backend.utils.validation import HexAddress


class DecompileResult(NamedTuple):
    success: bool
    result: str  # either the pseudocode result or an error message


class IndexingState(StrEnum):
    """Lifecycle of an on-disk index across (possibly interrupted) streaming runs."""

    DECOMPILING = "DECOMPILING"
    CLASSIFYING = "CLASSIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class BlacklistReason(StrEnum):
    """Why a function was skipped rather than decompiled."""

    DECOMPILE_TIMEOUT = "decompile_timeout"
    RPC_ERROR = "rpc_error"
    SIZE_LIMIT = "size_limit"
    UNKNOWN = "unknown"


class FunctionClassification(TypedDict):
    name: str
    pseudocode: str
    tags: list[str]
    summary: str
    key_operations: list[str]
    key_constants: list[str]
    called_apis: list[str]


class BlacklistEntry(TypedDict):
    name: str
    reason: BlacklistReason


class IndexResult(TypedDict):
    version: str
    sha256: str
    functions: dict[HexAddress, FunctionClassification]
    blacklist: dict[HexAddress, BlacklistEntry]
