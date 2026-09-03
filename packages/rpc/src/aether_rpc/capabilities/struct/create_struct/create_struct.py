import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.create_struct.constants import TYPE_MAP
from aether_rpc.capabilities.struct.types import StructField, StructResult


class CreateStruct(Capability):
    @property
    def name(self) -> str:
        return "create_struct"

    def _make_member(self, field: StructField, offset: int) -> ida_typeinf.udm_t | None:
        member = ida_typeinf.udm_t()
        member.name = field.name
        member.offset = offset
        member.type = ida_typeinf.tinfo_t()

        til = ida_typeinf.get_idati()
        base = ida_typeinf.tinfo_t()
        if not base.get_named_type(til, field.type):
            type_code = TYPE_MAP.get(field.type)

            if type_code is None or not base.create_simple_type(type_code):
                return None

        if field.array_length is not None:
            member.type.create_array(base, field.array_length)
        else:
            member.type = base

        return member

    def execute(
        self, struct_name: str, fields: list[StructField] | None = None
    ) -> Result[StructResult]:
        """Creates a new struct.

        Args:
            struct_name: Name of the struct to create.
            fields: Optional list of field definitions. If omitted, an
                empty struct is created.

                Each field must be specified as either:
                - ["field_name", "field_type"]
                - ["field_name", "field_type", array_length]

                Where:
                - ``field_name`` is the member name.
                - ``field_type`` is the member type (for example, ``uint32_t`` or ``char``).
                - ``array_length`` is an optional positive integer specifying the number
                of elements if the member is an array.

        Returns:
            A Result whose ``success`` indicates whether the struct was created
            successfully and whose ``result`` contains the created struct's ID and
            name.
        """
        # Create an empty struct
        tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()
        udt.pack = 1
        if fields:
            if not isinstance(fields, list):
                return Err(result="Fields must contain a list.")
            try:
                fields = [StructField(*field) for field in fields]
                offset = 0
                for field in fields:
                    member = self._make_member(field, offset)
                    if member is None:
                        return Err(
                            result="Invalid type for field. Please provide a user-defined type or use one of the following supported types: uint8_t, uint16_t, word, uint32_t, dword, uint64_t, int8_t, int16_t, short, int32_t, long, int64_t, char, bool, byte, float, double, or void."
                        )
                    offset += member.type.get_size() * 8
                    udt.push_back(member)
            except (ValueError, TypeError, SystemError):
                return Err(
                    result="Invalid fields. Each field must be a tuple containing a field "
                    "name and type, with an optional array length, for example: "
                    '[("id", "uint32_t"), ("name", "char", 32)].'
                )

        # Create the UDT
        if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            return Err(result="Failed to create named struct.")

        # Register it as a named type
        idati = ida_typeinf.get_idati()
        if not tif.set_named_type(idati, struct_name, ida_typeinf.NTF_REPLACE):
            return Ok(
                result=StructResult(
                    struct_id=tif.get_tid(),
                    struct_name=struct_name,
                )
            )
        else:
            return Err(result="Failed to create named struct.")
