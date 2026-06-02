from typing import Any

from pydantic import BaseModel, Field


class IDAContext(BaseModel):
    """IDA database state — what the binary looks like."""

    idb_path: str
    architecture: str | None = None
    bitness: int | None = None  # 32 or 64
    entry_point: int | None = None

    # default_factory=list transfers perfectly to manage mutable list structures safely
    segment_map: list[dict[str, Any]] = Field(default_factory=list)
    functions: list[dict[str, Any]] = Field(default_factory=list)


class ServerContext(BaseModel):
    """The unified server wrapper layout."""

    ida: IDAContext
    callback_url: str
