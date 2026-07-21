from aether_backend.utils.validation import HexAddress
from pydantic import BaseModel, RootModel


class InterestingFunction(BaseModel):
    address: HexAddress
    reason: str


class InterestingFunctions(RootModel[list[InterestingFunction]]):
    pass
