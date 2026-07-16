from typing import TypedDict

from aether_backend.utils.validation import HexAddress


class InterestingFunc_TD(TypedDict):
    address: HexAddress
    reason: str
