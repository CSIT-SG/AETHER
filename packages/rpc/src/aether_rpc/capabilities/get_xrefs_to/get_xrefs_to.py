import ida_name
import idautils

from aether_rpc.capabilities.types import XrefsResult

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StackVariableInfo
from ..utils import (
    collect_stkvar_xrefs,
    collect_xrefs,
    resolve_effective_address,
    resolve_stack_variable,
)


class GetXrefsTo(Capability):
    """Retrieves all cross-references pointing to a given address or symbol."""

    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def stack_var(
        self,
        location: str | int,
        variable: str,
    ) -> Result[XrefsResult]:
        """Find all locations that reference the given local/stack variable.

        Args:
            location (str | int): The target to look up cross-references for.
                Identifies the *function* that owns the stack variable (name,
                hex address, or effective address).
            variable (str | None): The name of a local/stack variable (e.g.
                "var_10" or a renamed local) inside the function identified
                by `location`. `location` and `variable` act as a compound
                key identifying one stack variable.

        Returns:
            Ok[XrefsResult]: A structured object containing:
                - target_address (str): The resolved hex address of the
                target, or the frame-relative start offset (hex) if
                `variable` was given.
                - target_name (str | None): The symbolic name of the target,
                e.g. "assign_buffer::var_10" for stack variables.
                - count (int): The number of cross-references found.
                - xrefs (list[XrefEntry]): The collected cross-reference
                entries.
            Err[str]: An error message string in the following cases:
                - The location (or function/variable pair) could not be
                resolved.
                - An exception was raised while collecting cross-references.

        Examples:
            execute("assign_buffer", variable="var_10")
            execute("0x140001000", variable="buf_ptr")
        """
        stack_var: StackVariableInfo | None = resolve_stack_variable(location, variable)
        if stack_var is None:
            return Err(result=f"Invalid stack variable '{variable}' in function {location}")
        try:
            xrefs = collect_stkvar_xrefs(stack_var)
        except Exception as e:
            self.logger.exception(
                "Failed to collect xrefs for stack var %s::%s: %s",
                location,
                variable,
                e,
            )
            return Err(result=f"Failed to collect xrefs for stack var {location}::{variable}: {e}")
        if xrefs is None:
            return Err(result=f"failed to resolve {stack_var}")
        data: XrefsResult = XrefsResult(
            target_address=hex(stack_var["start_off"]),
            target_name=f"{location}::{variable}",
            count=len(xrefs),
            xrefs=xrefs,
        )
        return Ok(data)

    def not_stack_var(
        self,
        location: str | int,
    ) -> Result[XrefsResult]:
        """Find all locations that reference the given address or symbol name.

        Args:
            location (str | int): The target to look up cross-references for.
                Accepts a hex address string (e.g. "0x140001000"), a plain
                symbol name (e.g. "assign_buffer"), an IDA auto-generated
                name (e.g. "sub_DEADBEEF"), or an integer effective address.

        Returns:
            Ok[XrefsResult]: A structured object containing:
                - target_address (str): The resolved hex address of the
                target.
                - target_name (str | None): The symbolic name of the target.
                - count (int): The number of cross-references found.
                - xrefs (list[XrefEntry]): The collected cross-reference
                entries.
            Err[str]: An error message string in the following cases:
                - The location could not be resolved.
                - An exception was raised while collecting cross-references.

        Examples:
            execute("assign_buffer")
            execute("0x140001000")
            execute("sub_DEADBEEF")
        """
        ea: int | None = resolve_effective_address(location)
        if ea is None:
            self.logger.error(f"Invalid location: {location}")
            return Err(result=f"Invalid location: {location}")

        try:
            xrefs = [collect_xrefs(x) for x in idautils.XrefsTo(ea)]
        except Exception as e:
            self.logger.exception("Failed to collect xrefs at %s: %s", hex(ea), e)
            return Err(result=f"Failed to collect xrefs at {hex(ea)}: {e}")

        data = XrefsResult(
            target_address=hex(ea),
            target_name=ida_name.get_name(ea) or None,
            count=len(xrefs),
            xrefs=xrefs,
        )

        return Ok(result=data)

    def execute(
        self,
        location: str | int,
        variable: str | None = None,
    ) -> Result[XrefsResult]:
        """Find all locations that reference the given address, symbol name,
        or local/stack variable.

        Args:
            location (str | int): The target to look up cross-references for.
                When `variable` is None, this accepts a hex address string
                (e.g. "0x140001000"), a plain symbol name (e.g.
                "assign_buffer"), an IDA auto-generated name (e.g.
                "sub_DEADBEEF"), or an integer effective address. When
                `variable` is provided, this identifies the *function* that
                owns the stack variable (name, hex address, or effective
                address).
            variable (str | None): The name of a local/stack variable (e.g.
                "var_10" or a renamed local) inside the function identified
                by `location`. If provided, `location` and `variable` act as
                a compound key identifying one stack variable. If omitted,
                `location` is resolved as a normal global address/symbol.

        Returns:
            Ok[XrefsResult]: A structured object containing:
                - target_address (str): The resolved hex address of the
                target, or the frame-relative start offset (hex) if
                `variable` was given.
                - target_name (str | None): The symbolic name of the target,
                e.g. "assign_buffer::var_10" for stack variables.
                - count (int): The number of cross-references found.
                - xrefs (list[XrefEntry]): The collected cross-reference
                entries.
            Err[str]: An error message string in the following cases:
                - The location (or function/variable pair) could not be
                resolved.
                - An exception was raised while collecting cross-references.

        Examples:
            execute("assign_buffer")
            execute("0x140001000")
            execute("sub_DEADBEEF")
            execute("assign_buffer", variable="var_10")
            execute("0x140001000", variable="buf_ptr")
        """
        if variable is None:
            result = self.not_stack_var(location=location)
        else:
            result = self.stack_var(location=location, variable=variable)
        return result
