import ida_bytes
import ida_funcs
import idaapi
import idc

from ..base import Capability
from ..utils import decompile_or_none, resolve_effective_address


class SetComment(Capability):
    """Attaches or updates a comment at a given address in the IDA decompiler view.

    Handles two distinct comment targets:
    - Function header: the definition line at the top of the pseudocode
    - Inline statement: any address inside the decompiled function body
    """

    @property
    def name(self) -> str:
        return "set_comment"

    def execute(self, address: str, comment: str) -> None:
        """Resolve the address and dispatch to the appropriate comment strategy.

        Args:
            address: Hex or decimal string address of the comment target.
            comment: Text to write. Pass an empty string to clear.
        """
        ea = resolve_effective_address(address)
        cfunc = decompile_or_none(ea)

        if cfunc is None:
            self.logger.error(f"Failed to decompile at {hex(ea)}")
            return

        if ea == cfunc.entry_ea:
            self._comment_function_header(cfunc, ea, comment)
        else:
            self._comment_inline(cfunc, ea, comment)

    def _comment_function_header(self, cfunc, ea: int, comment: str) -> None:
        """Write a comment at the function header line using idc."""
        idc.set_func_cmt(ea, comment, 1)
        cfunc.refresh_func_ctext()

    def _comment_inline(self, cfunc, ea: int, comment: str) -> None:
        """Write a comment at an inline statement inside the function body."""
        ea = self._nearest_mapped_ea(cfunc, ea)
        loc = self._comment_location(ea)
        self._clear_slots(cfunc, loc)
        if comment:
            self._write_to_slot(cfunc, loc, comment)
        cfunc.refresh_func_ctext()

    def _nearest_mapped_ea(self, cfunc, ea: int) -> int:
        """Walk backward from ea to find the nearest address mapped in the ctree.

        IDA's eamap does not always contain every address — compound statements
        may only appear at an earlier EA. This method finds the closest predecessor
        that has a valid ctree node.

        Raises:
            LookupError: If no mapped address is found within the function bounds.
        """
        eamap = cfunc.get_eamap()
        if ea in eamap:
            return ea

        func = ida_funcs.get_func(ea)
        if func is None:
            raise LookupError(f"no function at {hex(ea)}")

        search = ea
        while search >= func.start_ea:
            if search in eamap:
                return search
            search = ida_bytes.prev_head(search, func.start_ea)
            if search == idaapi.BADADDR:
                raise LookupError(f"walked off the ctree map near {hex(ea)}")

        raise LookupError(f"no ctree node found near {hex(ea)}")

    def _comment_location(self, ea: int) -> idaapi.treeloc_t:
        """Create a treeloc_t pointing at the given address."""
        loc = idaapi.treeloc_t()
        loc.ea = ea
        return loc

    def _clear_slots(self, cfunc, loc: idaapi.treeloc_t) -> None:
        """Clear both ITP_SEMI and ITP_BLOCK1 comment slots at the given location.

        Prevents stale comments from persisting alongside the new one.
        """
        for slot in (idaapi.ITP_SEMI, idaapi.ITP_BLOCK1):
            loc.itp = slot
            cfunc.set_user_cmt(loc, "")

    def _write_to_slot(self, cfunc, loc: idaapi.treeloc_t, comment: str) -> None:
        """Write the comment to ITP_SEMI, falling back to ITP_BLOCK1 if orphaned.

        IDA may mark a comment as an orphan if the ctree node at save time does
        not match. In that case the comment is retried at ITP_BLOCK1 which attaches
        before the block rather than at the end of the line.
        """
        loc.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(loc, comment)
        cfunc.save_user_cmts()

        if cfunc.has_orphan_cmts():
            cfunc.set_user_cmt(loc, "")
            loc.itp = idaapi.ITP_BLOCK1
            cfunc.set_user_cmt(loc, comment)
            cfunc.save_user_cmts()
