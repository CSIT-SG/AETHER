from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.struct.types import ChangeStructFieldTypeResult


async def change_struct_field_type(
    service: AnyService, *, struct: str | int, field_name: str, new_type: str
) -> Result[ChangeStructFieldTypeResult]:
    """Change struct field type.

    Args:
        struct: The name or id of the struct to add the field to.
        field_name: Name of field which type is to be changed.
        new_type: New type of field.

    Returns:
        A Result object whose ``result`` attribute contains the outcome.
    """
    return service.change_struct_field_type(struct=struct, field_name=field_name, new_type=new_type)
