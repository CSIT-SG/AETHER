import ida_bytes
import ida_ida
import yara_x

from ...base import Capability
from ...result import Err, Ok, Result


class ValidateYaraRule(Capability):
    """Compiles a YARA rule with yara-x and checks it against the current binary."""

    @property
    def name(self) -> str:
        return "validate_yara_rule"

    def _read_loaded_binary_bytes(self) -> bytes | None:
        """Read all loaded segment bytes from IDA's database, in address order."""
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        return ida_bytes.get_bytes(min_ea, max_ea - min_ea)

    def execute(self, rule_text: str) -> Result[str]:
        """Compile a single YARA rule and test it against the binary loaded in IDA.

        Args:
            rule_text: Full source of a single YARA rule (e.g. "rule X { ... }").

        Returns:
            A Result whose ``success`` reports whether the rule compiled AND
            matched the binary. ``result`` is the rule name on success, or an
            error message on failure.
        """

        binary_data = self._read_loaded_binary_bytes()
        if not binary_data:
            self.logger.error("Failed to read loaded binary bytes from IDA database")
            return Err(result="Failed to read loaded binary bytes from IDA database")

        try:
            compiled_rules = yara_x.compile(rule_text)
            _names = [rule.identifier for rule in compiled_rules]
            if len(_names) != 1:
                self.logger.error("Expected exactly one rule in the input, found %d", len(_names))
                return Err(result=f"Expected exactly one rule in the input, found {len(_names)}")
            rule_name = _names[0]
        except Exception as e:
            self.logger.error("Rule text %r failed to compile: %s", rule_text, e)
            return Err(result=f"Rule text {rule_text!r} failed to compile: {e}")

        try:
            scanner = yara_x.Scanner(compiled_rules)
            scan_results = scanner.scan(binary_data)
            matched = len(scan_results.matching_rules) > 0
        except Exception as e:
            self.logger.error("Rule %r failed during scan: %s", rule_name, e)
            return Err(result=f"Rule {rule_name!r} failed during scan: {e}")

        if not matched:
            self.logger.error("Rule %r did not match binary", rule_name)
            return Err(result=f"Rule {rule_name!r} did not match binary")

        return Ok(result=rule_name)
