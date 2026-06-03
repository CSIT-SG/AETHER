from ..base import Capability
from ..utils import (
    collect_xrefs,
    function_info,
    name_or_address,
    resolve_effective_address,
    symbol_hints,
)


class GetXrefsTo(Capability):
    """Retrieves all cross-references pointing to a given address or symbol."""

    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def execute(self, location: str) -> str:
        """Find all locations that reference the given address or symbol name.

        Args:
            location: Hex address or symbol name of the target.

        Returns:
            Formatted string listing all xrefs, or an error message if
            the target could not be resolved.
        """
        ea = resolve_effective_address(location)
        preview, total, warnings = collect_xrefs(ea)
        return self._format_output(location, ea, preview, total, warnings)

    def _format_output(self, location: str, ea: int, preview: list, total: int, warnings: list) -> str:
        """Format xref results into a human and LLM readable string."""
        name = name_or_address(ea)
        context, _ = function_info(ea)

        header = [
            f"Target {name} @ {hex(ea)} [{context}]",
            f"Symbol hints: {symbol_hints(name)}",
        ]

        if not preview:
            body = [f"No cross-references found for '{location}'."]
        else:
            body = [f"Found {total} xrefs to '{location}':"]
            for x in preview:
                flag = "yes" if x["is_function_start"] else "no"
                body.append(f"  - {x['from']} in {x['name']} ({x['type']}) [{x['context']}] [function_start:{flag}]")

        if warnings:
            body += [f"Warnings: {len(warnings)}"] + [f"  - {w}" for w in warnings[:5]]

        return "\n".join(header + body)
