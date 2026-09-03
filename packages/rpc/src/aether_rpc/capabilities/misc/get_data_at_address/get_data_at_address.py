import ida_bytes
import ida_ida
import ida_lines
import ida_nalt
import ida_name
import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.function_utils import function_info
from aether_rpc.capabilities.misc.address_utils import resolve_effective_address
from aether_rpc.capabilities.misc.types import AddressData, PointerInfo
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.variables.xref_utils import collect_xrefs
from idautils import XrefsFrom, XrefsTo


class GetDataAtAddress(Capability):
    """Retrieves raw data, disassembly, string, pointer, and xref context at a given address."""

    @property
    def name(self) -> str:
        return "get_data_at_address"

    def execute(self, location: str | int) -> Result[AddressData]:
        """Collect and return all available data at the given address or symbol.

        Args:
            location: Hex address or symbol name of the target.

        Returns:
            A Result whose ``result`` holds the collected AddressData on success,
            or an error message if the address could not be resolved or loaded.
        """
        ea = resolve_effective_address(location)
        if ea is None:
            self.logger.error("Error: Could not resolve '%s'.", location)
            return Err(result=f"Could not resolve '{location}'")

        if not ida_bytes.is_loaded(ea):
            self.logger.error("Address %s is not loaded in the database", hex(ea))
            return Err(result=f"Address {hex(ea)} is not loaded in the database")

        flags = ida_bytes.get_flags(ea)
        item_size = max(ida_bytes.get_item_size(ea), 1)
        raw = ida_bytes.get_bytes(ea, item_size)
        raw_bytes: str = raw.hex() if raw is not None else ""

        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tif, ea)
        data = AddressData(
            address=hex(ea),
            name=ida_name.get_name(ea) or None,
            type=str(tif.get_type_name()),
            function=function_info(ea),
            item_size=item_size,
            raw_bytes=raw_bytes,
            is_code=bool(ida_bytes.is_code(flags)),
            is_data=bool(ida_bytes.is_data(flags)),
            disassembly=self._get_disassembly(ea, flags),
            string=self._get_string(ea, flags),
            pointer=self._get_pointer(ea, flags),
            xrefs_to=[collect_xrefs(x) for x in XrefsTo(ea)],
            xrefs_from=[collect_xrefs(x) for x in XrefsFrom(ea)],
        )

        return Ok(result=data)

    def _get_disassembly(self, ea: int, flags: int) -> str | None:
        """Return the disassembly line at ``ea``, or ``None`` if not code.

        Uses ``generate_disasm_line`` and strips IDA's color tags so the
        returned string matches what is shown in the disassembly view.

        Args:
            ea: Effective address to disassemble.
            flags: Pre-fetched flags for ``ea`` from ``ida_bytes.get_flags``.

        Returns:
            The plain-text disassembly line, or ``None`` if ``ea`` is not
            marked as code or no line could be generated.
        """

        if not ida_bytes.is_code(flags):
            return None
        line = ida_lines.generate_disasm_line(ea, 0)
        if line is None:
            return None
        return ida_lines.tag_remove(line)

    def _get_string(self, ea: int, flags: int) -> str | None:
        """Return the string literal at ``ea``, or ``None`` if not a string.

        Only returns a value when ``ea`` is explicitly defined as a string
        literal in the database; raw bytes that happen to look like a string
        are not detected. Undecodable bytes are replaced rather than raising.

        Args:
            ea: Effective address of the string literal.
            flags: Pre-fetched flags for ``ea`` from ``ida_bytes.get_flags``.

        Returns:
            The decoded string contents, or ``None`` if ``ea`` is not a
            string literal or its contents could not be read.
        """

        if not ida_bytes.is_strlit(flags):
            return None
        strtype = ida_nalt.get_str_type(ea)
        contents = ida_bytes.get_strlit_contents(ea, -1, strtype)
        if contents is None:
            return None
        return contents.decode("utf-8", errors="replace")

    def _get_pointer(self, ea: int, flags: int) -> PointerInfo | None:
        """Return pointer info if ``ea`` holds a value that points into the database.

        Reads a pointer-sized word at ``ea`` (8 bytes on 64-bit databases,
        4 bytes on 32-bit) and reports it only when the value resolves to a
        loaded address. This filters out arbitrary integers that happen to
        look like pointers.

        Args:
            ea: Effective address to read the candidate pointer from.
            flags: Pre-fetched flags for ``ea`` from ``ida_bytes.get_flags``.

        Returns:
            A PointerInfo instance with ``value`` (hex string of the target address) and
            ``name`` (symbol at the target, or ``None``), or ``None`` if
            ``ea`` is not data or the value does not point into the database.
        """

        if not ida_bytes.is_data(flags):
            return None
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        ptr_value = ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)
        if not ida_bytes.is_loaded(ptr_value):
            return None
        return {
            "value": hex(ptr_value),
            "name": ida_name.get_name(ptr_value) or None,
        }
