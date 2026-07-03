from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field

from .constants import _VALID_INPUT


def _normalize_hex(v: str) -> str | None:
    stripped = v.strip().lower()
    match = _VALID_INPUT.fullmatch(stripped)
    if not match:
        return None

    hex_part = match["prefixed_hex"] or match["unprefixed_hex"]

    return f"0x{hex_part}"


type HexAddress = Annotated[
    str,
    BeforeValidator(_normalize_hex),
    Field(
        pattern=r"^0x[0-9a-f]+$",  # ensures the result is a valid hex address
        description="Hex address in format '0x<hex>'. Uppercase input is normalized to lowercase.",
        examples=["0x140009050", "0xffff"],
    ),
]


class AddressModel(BaseModel):
    address: HexAddress
