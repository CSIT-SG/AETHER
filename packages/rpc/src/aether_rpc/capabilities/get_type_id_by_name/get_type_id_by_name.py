import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from .constants import INVALID_TYPE


class GetTypeIdByName(Capability):
    """Retrieves the type ID associated with the specified type name."""

    @property
    def name(self) -> str:
        return "get_type_id_by_name"

    def execute(self, type_name: str) -> Result[int]:
        """Retrieves the type ID associated with the specified type name.

        Args:
            type_name: The name of the type to look up.

        Returns:
            A Result object whose ``result`` attribute contains the corresponding
            type ID.
        """
        type_id = ida_typeinf.get_named_type_tid(type_name)
        if type_id == INVALID_TYPE:
            return Err(result="Type with the specified name does not exist.")
        return Ok(result=type_id)
