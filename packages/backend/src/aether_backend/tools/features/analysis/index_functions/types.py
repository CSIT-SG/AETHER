from typing import NamedTuple


class PseudocodeYield(NamedTuple):
    success: bool
    result: str  # either the pseudocode result or an error message
