import ida_typeinf


from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructResult
from .constants import TYPE_MAP


class CreateStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "create_struct"

    def execute(self,  struct_name: str, fields: list[tuple[str, str, int | None]] | None = None) -> Result[StructResult]:
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
                return Err(result="""Fields must contain a list.""")
            try:
                next_offset = 0
                for field in fields:
                    member = ida_typeinf.udm_t()
                    member.name = field[0]
                    member.offset = next_offset
                    member.type = ida_typeinf.tinfo_t()
                    if len(field) == 3:
                        base = ida_typeinf.tinfo_t()
                        base.create_simple_type(TYPE_MAP[field[1]])
                        member.type.create_array(base, field[2])
                    elif len(field) == 2:
                        member.type.create_simple_type(TYPE_MAP[field[1]])
                    else:
                        return Err(result="""Fields must only have the length of 2 or 3.""")
                    next_offset = next_offset + member.type.get_size() * 8
                    udt.push_back(member)
            except KeyError:
                return Err(result=f"""Invalid type for field.""")
            except (ValueError, TypeError, SystemError):
                return Err(result='Invalid fields. Each field must be a tuple containing a field '
                           'name and type, with an optional array size, for example: '
                           '[("id", "uint32_t"), ("name", "char", 32)].')


        # Create the UDT
        if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            return Err(result=f"Failed to create named struct.")

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
            return Err(result=f"Failed to create named struct.")