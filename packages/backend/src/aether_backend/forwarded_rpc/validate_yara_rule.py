from aether_backend.utils.get_rpc_service.types import AnyService
from aether_rpc.capabilities.result import Result


async def validate_yara_rule(service: AnyService, *, rule_text: str) -> Result[str]:
    """Compile a single YARA rule with yara-x and test it against the binary
    currently loaded in IDA.

    Reads all loaded segment bytes from the IDA database (in address order),
    compiles the given rule text, and scans the binary for a match. The rule
    must both compile successfully and match the loaded binary to be
    considered valid.

    Args:
        rule_text (str): Full source of a single YARA rule
            (e.g. "rule X { strings: $a = /foo/i condition: $a }").

    Returns:
        Ok[str]: The rule's identifier (name) if it compiled and matched.
        Err[str]: An error message string in the following cases:
            - The loaded binary's bytes could not be read from the IDA database.
            - The rule text did not contain exactly one rule definition.
            - The rule failed to compile.
            - The rule failed during scanning.
            - The rule compiled but did not match the loaded binary.

    Example:
        validate_yara_rule(rule_text="rule Foo { strings: $a = /bar/i condition: $a }")
    """
    return service.validate_yara_rule(rule_text=rule_text)
