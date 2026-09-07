from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import ChangeStructFieldSizeResult


async def change_struct_field_size(
    service: AnyService, *, struct: str | int, field_name: str, new_size: int
) -> Result[ChangeStructFieldSizeResult]:
    """Change size of a struct field.

    Args:
        struct: The name of the sturct containing field to be changed.
        field_name: Name of field to be resized.
        new_size: Integer valu for the new size of field.

    Returns:
        A Result object whose ``result`` attribute contains the outcome.
    """
    return service.change_struct_field_size(struct=struct, field_name=field_name, new_size=new_size)
