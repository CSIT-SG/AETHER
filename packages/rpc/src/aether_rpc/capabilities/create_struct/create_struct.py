import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructField, StructResult
from .constants import TYPE_MAP


class CreateStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "create_struct"

    def _make_member(self, field: StructField, offset: int) -> ida_typeinf.udm_t:
        member = ida_typeinf.udm_t()
        member.name = field.name
        member.offset = offset
        member.type = ida_typeinf.tinfo_t()

        base = ida_typeinf.tinfo_t()
        base.create_simple_type(TYPE_MAP[field.type])

        if field.array_size is not None:
            member.type.create_array(base, field.array_size)
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
                    offset += member.type.get_size() * 8
                    udt.push_back(member)
            except KeyError:
                return Err(result="Invalid type for field.")
            except (ValueError, TypeError, SystemError):
                return Err(
                    result="Invalid fields. Each field must be a tuple containing a field "
                    "name and type, with an optional array size, for example: "
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
