import ida_typeinf

from ..base import Capability

# --- Field Parsing ---


def _parse_field(til, name: str, t_str: str, offset: int) -> tuple | None:
    """Parse a single field declaration into a tinfo_t object.

    Attempts to resolve the type string against IDA's type library.
    Returns None if the type string is invalid or unresolvable.

    Args:
        til: IDA's local type information library.
        name: Field name.
        t_str: C type string e.g. 'uint32_t', 'void*', 'int[10]'.
        offset: Field byte offset within the struct.

    Returns:
        Tuple of (name, tinfo_t, start_bits) if parsing succeeded, None otherwise.
    """
    tmp_tif = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tmp_tif, til, t_str + ";", 0)

    # parse_decl succeeds silently even on failure — check the result is non-empty
    if len(str(tmp_tif)) == 0:
        return None

    return name, tmp_tif, offset * 8


# --- Overlap Detection ---


def _has_overlap(m_start: int, m_end: int, occupied_ranges: list[tuple[int, int]]) -> bool:
    """Return True if [m_start, m_end) overlaps any range in occupied_ranges.

    Ranges are in bits. A member overlaps if it starts before another ends
    and ends after another starts.

    Args:
        m_start: Start bit offset of the member to check.
        m_end: End bit offset of the member to check.
        occupied_ranges: List of (start_bits, end_bits) tuples already occupied.
    """
    return any(m_start < n_end and m_end > n_start for n_start, n_end in occupied_ranges)


class DeclareCStruct(Capability):
    """Creates or updates a struct in IDA's type library from a list of field tuples.

    Existing members that do not overlap with the new fields are preserved.
    Members that overlap with incoming fields are replaced.
    """

    @property
    def name(self) -> str:
        return "declare_c_struct"

    def execute(self, struct_name: str, fields_list: list, struct_size: int = 0) -> list:
        """Create or update a struct using a list of (name, type_str, offset) tuples.

        Args:
            struct_name: Name of the struct to create or update e.g. 'MyStruct'.
            fields_list: List of (name, type_str, offset) tuples e.g.
                         [('magic', 'uint32_t', 0x0), ('version', 'uint16_t', 0x4)]
            struct_size: Optional known total size in bytes.

        Returns:
            List of (name, type_str, offset) tuples that failed to parse.
        """
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        udt_data = ida_typeinf.udt_type_data_t()

        self._load_or_create(tif, til, udt_data, struct_name)
        udt_data.taudt_bits |= ida_typeinf.TAUDT_FIXED

        new_members, occupied_ranges, failed_list, max_bit_reached = self._parse_fields(
            til, fields_list, struct_size * 8
        )
        new_members, max_bit_reached = self._merge_existing(
            udt_data, new_members, occupied_ranges, max_bit_reached
        )
        self._commit(tif, til, udt_data, struct_name, new_members, max_bit_reached)

        return failed_list

    def _load_or_create(self, tif, til, udt_data, struct_name: str) -> None:
        """Load an existing struct into udt_data, or initialise a new empty one.

        If the struct already exists in the type library it is loaded so that
        existing members can be preserved. Otherwise a fresh empty struct is
        registered under the given name.

        Args:
            tif: tinfo_t object to populate.
            til: IDA's local type information library.
            udt_data: udt_type_data_t object to populate with existing members.
            struct_name: Name of the struct to load or create.
        """
        if tif.get_named_type(til, struct_name):
            tif.get_udt_details(udt_data)
            self.logger.info(f"Updating existing struct: {struct_name}")
        else:
            self.logger.info(f"Creating new struct: {struct_name}")
            tif.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
            tif.set_named_type(
                til,
                struct_name,
                ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE,
            )

    def _parse_fields(
        self, til, fields_list: list, max_bit_reached: int
    ) -> tuple[list, list[tuple[int, int]], list, int]:
        """Parse incoming fields into tinfo_t objects and track their bit ranges.

        Args:
            til: IDA's local type information library.
            fields_list: List of (name, type_str, offset) tuples to parse.
            max_bit_reached: Initial max bit offset, typically struct_size * 8.

        Returns:
            Tuple of (new_members, occupied_ranges, failed_list, max_bit_reached).
        """
        new_members: list = []
        occupied_ranges: list[tuple[int, int]] = []
        failed_list: list = []

        for field_name, t_str, offset in fields_list:
            parsed = _parse_field(til, field_name, t_str, offset)
            if parsed is None:
                failed_list.append((field_name, t_str, offset))
                continue

            name, tmp_tif, start_bits = parsed
            end_bits = start_bits + tmp_tif.get_size() * 8
            max_bit_reached = max(max_bit_reached, end_bits)
            new_members.append((name, tmp_tif, start_bits))
            occupied_ranges.append((start_bits, end_bits))

        return new_members, occupied_ranges, failed_list, max_bit_reached

    def _merge_existing(
        self,
        udt_data,
        new_members: list,
        occupied_ranges: list[tuple[int, int]],
        max_bit_reached: int,
    ) -> tuple[list, int]:
        """Merge existing non-overlapping members into the new member list.

        Existing members that overlap with incoming fields are discarded.
        All others are preserved alongside the new fields.

        Args:
            udt_data: Existing UDT data to merge from.
            new_members: Already parsed incoming members.
            occupied_ranges: Bit ranges occupied by incoming fields.
            max_bit_reached: Current max bit offset.

        Returns:
            Tuple of (merged members list, updated max_bit_reached).
        """
        for member in udt_data:
            size = member.type.get_size()
            if size == 0xFFFFFFFFFFFFFFFF:
                # Skip members with invalid or unknown size
                continue

            m_start = member.offset
            m_end = (m_start + size * 8) & 0xFFFFFFFF
            max_bit_reached = max(max_bit_reached, m_end)

            if _has_overlap(m_start, m_end, occupied_ranges):
                self.logger.warning(
                    f"Removing overlapping member '{member.name}' at {m_start // 8:#x}"
                )
            else:
                new_members.append((member.name, member.type, member.offset))

        return new_members, max_bit_reached

    def _commit(
        self,
        tif,
        til,
        udt_data,
        struct_name: str,
        new_members: list,
        max_bit_reached: int,
    ) -> None:
        """Build the final UDT and commit it to IDA's type library.

        Members are sorted by offset before being pushed into the UDT.

        Args:
            tif: tinfo_t object to commit.
            til: IDA's local type information library.
            udt_data: Original UDT data, used to preserve struct attributes.
            struct_name: Name to register the struct under.
            new_members: Final merged list of (name, tinfo_t, offset_bits) tuples.
            max_bit_reached: Total struct size in bits.
        """
        final_udt = ida_typeinf.udt_type_data_t()
        final_udt.taudt_bits = udt_data.taudt_bits
        final_udt.total_size = max_bit_reached // 8

        for name, m_tif, m_offset in sorted(new_members, key=lambda x: x[2]):
            new_member = ida_typeinf.udt_member_t()
            new_member.name = name
            new_member.type = m_tif
            new_member.offset = m_offset
            final_udt.push_back(new_member)

        if tif.create_udt(final_udt, ida_typeinf.BTF_STRUCT):
            tif.set_named_type(
                til,
                struct_name,
                ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE,
            )
            self.logger.info(
                f"Successfully upserted '{struct_name}' with {len(new_members)} fields."
            )
        else:
            self.logger.error(f"Could not save struct '{struct_name}'.")
