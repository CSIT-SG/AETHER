from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import StructFieldResult


async def add_struct_field(
    service: AnyService,
    *,
    struct: str | int,
    field_name: str,
    field_type: str,
    offset: int,
    array_length: int | None,
) -> Result[StructFieldResult]:
    """Add a field to a structure.

    Args:
        struct: The name or id of the struct to add the field to.
        field_name: Name of the new field.
        field_type: Type of the new field.
        offset: Byte offset in decimal at which to add the field.
        array_length: Optional if type is not an array. Number of elements if the field is an array.

    Returns:
        A Result whose ``success`` reports whether the add succeeded and
        whose ``result`` carries struct id, struct name, field name, field
        type, and array size if applicable.
    """
    return service.add_struct_field(
        struct=struct,
        field_name=field_name,
        field_type=field_type,
        offset=offset,
        array_length=array_length,
    )
