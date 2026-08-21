from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import StructFieldResult


async def delete_struct_field(
    service: AnyService,
    *struct: str | int,
    field_name: str,
) -> Result[StructFieldResult]:
    """Delete a field from a structure and compact the remaining fields.

    Args:
        struct: The name or id of the struct to delete the field from.
        field_name: Name of the field to delete.

    Returns:
        A Result whose ``success`` reports whether the deletion succeeded
        and whose ``result`` carries struct id, struct name, and field name.
    """
    return service.delete_struct_field(struct=struct, field_name=field_name)
