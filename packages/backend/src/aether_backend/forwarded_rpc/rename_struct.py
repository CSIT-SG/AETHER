from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameStructResult


async def rename_struct(
    service: AnyService, *, struct: str | int, new_name: str
) -> Result[RenameStructResult]:
    """Rename struct.

    Args:
        struct: The name or id of the struct to rename.
        new_name: The new name for struct to be renamed to.

    Returns:
        A Result whose ``success`` reports whether the rename succeeded and
        whose ``result`` carries struct id, old and new name
    """
    if not new_name.startswith("AETHER_"):
        new_name = "AETHER_" + new_name
    return service.rename_struct(struct=struct, new_name=new_name)
