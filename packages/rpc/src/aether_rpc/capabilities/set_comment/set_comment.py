import ida_bytes
import ida_funcs
import ida_hexrays
import idaapi
import idc

from ..base import Capability


class SetComment(Capability):
    @property
    def name(self) -> str:
        return "set_comment"

    def execute(self, address: str, comment: str):
        # Normalize address to integer, supporting both hex strings and decimal
        effective_address = (
            int(address, 16)
            if isinstance(address, str) and address.startswith("0x")
            else int(address)
        )

        # Snap to the start of the instruction/data item at this address,
        # since mid-item addresses are not valid comment targets
        effective_address = ida_bytes.get_item_head(effective_address)

        decompiled_function = ida_hexrays.decompile(effective_address)
        if decompiled_function is None:
            raise RuntimeError(f"failed to decompile at {hex(effective_address)}")

        # Function header comments are handled separately via idc rather than
        # treeloc, since the entry EA has no corresponding ctree node
        if effective_address == decompiled_function.entry_ea:
            idc.set_func_cmt(effective_address, comment, 1)
            decompiled_function.refresh_func_ctext()
            return

        # The eamap maps addresses to their corresponding ctree statements.
        # If the address is missing, we walk backward to find the nearest
        # mapped predecessor — this handles addresses inside compound statements
        # that IDA attributes to an earlier EA
        address_to_statement_map = decompiled_function.get_eamap()
        if effective_address not in address_to_statement_map:
            containing_function = ida_funcs.get_func(effective_address)
            if containing_function is None:
                raise LookupError(f"no function at {hex(effective_address)}")

            search_address = effective_address
            while search_address >= containing_function.start_ea:
                if search_address in address_to_statement_map:
                    effective_address = search_address
                    break
                search_address = ida_bytes.prev_head(search_address, containing_function.start_ea)
                if search_address == idaapi.BADADDR:
                    raise LookupError(f"prev_head walked off the map near {hex(effective_address)}")
            else:
                raise LookupError(f"no eamap entry found near {hex(effective_address)}")

        # treeloc_t identifies the exact ctree node to attach the comment to
        comment_location = idaapi.treeloc_t()
        comment_location.ea = effective_address

        # Clear any existing comments at both slot types before writing,
        # to avoid stale comments persisting alongside the new one
        for insertion_point in (idaapi.ITP_SEMI, idaapi.ITP_BLOCK1):
            comment_location.itp = insertion_point
            decompiled_function.set_user_cmt(comment_location, "")

        if comment:
            # ITP_SEMI places the comment at the end of the line (preferred).
            # If IDA marks it as an orphan (no matching ctree node at save time),
            # fall back to ITP_BLOCK1 which attaches before the block instead
            comment_location.itp = idaapi.ITP_SEMI
            decompiled_function.set_user_cmt(comment_location, comment)
            decompiled_function.save_user_cmts()

            if decompiled_function.has_orphan_cmts():
                comment_location.itp = idaapi.ITP_SEMI
                decompiled_function.set_user_cmt(comment_location, "")

                comment_location.itp = idaapi.ITP_BLOCK1
                decompiled_function.set_user_cmt(comment_location, comment)
                decompiled_function.save_user_cmts()

        decompiled_function.refresh_func_ctext()
