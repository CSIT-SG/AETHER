from aether_backend.utils.validation import HexAddress
from pydantic import BaseModel


class InterestingFunction(BaseModel):
    address: HexAddress
    reason: str


class InterestingFunctionOutput(BaseModel):
    functions: list[InterestingFunction]
