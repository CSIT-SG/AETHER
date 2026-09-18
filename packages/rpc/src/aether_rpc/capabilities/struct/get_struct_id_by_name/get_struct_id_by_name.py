from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.utils import get_struct_id_by_name


class GetStructIdByName(Capability):
    """Retrieves the struct ID associated with the specified struct name."""

    @property
    def name(self) -> str:
        return "get_struct_id_by_name"

    def execute(self, struct_name: str) -> Result[int]:
        """Retrieves the struct ID associated with the specified struct name.

        Args:
            struct_name: The name of the struct to look up.

        Returns:
            A Result object whose ``result`` attribute contains the corresponding
            struct ID.
        """
        struct_id = get_struct_id_by_name(struct_name)
        if struct_id is None:
            return Err(result="Struct with the specified name does not exist.")
        return Ok(result=struct_id)
