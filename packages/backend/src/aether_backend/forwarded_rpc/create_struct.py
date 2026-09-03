from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.struct.types import StructField, StructResult


async def create_struct(
    service: AnyService, *, struct_name: str, fields: list[StructField] | None = None
) -> Result[StructResult]:
    """Creates a new struct.

    Args:
        struct_name: Name of the struct to create.
        fields: Optional list of field definitions. If omitted, an
            empty struct is created.

            Each field must be specified as either:
            - ["field_name", "field_type"]
            - ["field_name", "field_type", array_size]

            Where:
            - ``field_name`` is the member name.
            - ``field_type`` is the member type (for example, ``uint32_t`` or ``char``).
            - ``array_size`` is an optional positive integer specifying the number
            of elements if the member is an array.

    Returns:
        A Result whose ``success`` indicates whether the struct was created
        successfully and whose ``result`` contains the created struct's ID and
        name.
    """
    return service.create_struct(struct_name=struct_name, fields=fields)
