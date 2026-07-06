from typing import Annotated

from pydantic import BeforeValidator, Field

from .constants import _VALID_INPUT


def _normalize_hex(v: str) -> str | None:
    match = _VALID_INPUT.fullmatch(v)
    if not match:
        return None

    hex_part = match["addr"]

    return f"0x{hex_part}"


type HexAddress = Annotated[
    str,
    BeforeValidator(_normalize_hex),
    Field(
        description="Hex address in format '0x<hex>'. Uppercase input is normalized to lowercase.",
        examples=["0x140009050", "0xffff"],
    ),
]
