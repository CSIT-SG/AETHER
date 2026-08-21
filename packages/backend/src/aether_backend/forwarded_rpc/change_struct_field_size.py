from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import ChangeStructFieldSizeResult


async def change_struct_field_size(
    service: AnyService, *, struct: str | int, field_name: str, new_size: str
) -> Result[ChangeStructFieldSizeResult]:
    """Change size of a struct field.

    Args:
        struct_id: The id of the type containing field to be changed.
        old_field_name: Original name of field to be renamed.
        new_field_name: New name of field to be renamed.

    Returns:
        A Result object whose ``result`` attribute contains the outcome.
    """
    return service.change_struct_field_size(struct=struct, field_name=field_name, new_size=new_size)
