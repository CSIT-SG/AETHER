from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameStructFieldResult


async def rename_struct_field(
    service: AnyService, *, struct: str | int, old_field_name: str, new_field_name: str
) -> Result[RenameStructFieldResult]:
    """Rename struct field.

    Args:
        struct: The name or id of the struct containing field to be changed.
        old_field_name: Original name of field to be renamed.
        new_field_name: New name of field to be renamed.

    Returns:
        A Result whose ``success`` reports whether the rename succeeded and
        whose ``result`` carries the struct id, name, old field name and new field name.
    """
    return service.rename_struct_field(
        struct=struct, old_field_name=old_field_name, new_field_name=new_field_name
    )
