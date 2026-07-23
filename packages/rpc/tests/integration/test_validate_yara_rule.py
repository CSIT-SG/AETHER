# type: ignore
from collections.abc import Callable
from pathlib import Path

import pytest
import rpyc


def _hex_pattern(data: bytes) -> str:
    """Render raw bytes as a YARA hex pattern, e.g. b'\\xAA\\xBB' -> '{ AA BB }'."""
    return "{ " + " ".join(f"{b:02X}" for b in data) + " }"


@pytest.mark.dependency(scope="package")
class TestValidateYaraRule:
    """Verifies that validate_yara_rule compiles, scans, and reports rule
    status against the actual binary loaded in the running IDA instance."""

    def test_rule_matching_known_string_in_binary_succeeds(
        self, ida_client: rpyc.Connection, get_binary: Callable[..., Path], BIN_NAME: str
    ) -> None:
        # "weird_payload" is a string literal compiled into foo_make()'s body,
        # so it's guaranteed to land in a loaded data segment IDA maps.
        rule_text = """
        rule known_string_match {
            strings:
                $a = "weird_payload"
            condition:
                $a
        }
        """

        result = ida_client.root.validate_yara_rule(rule_text=rule_text)

        assert result.success is True
        assert result.result == "known_string_match"

    def test_rule_with_absent_string_fails_to_match(
        self, ida_client: rpyc.Connection, get_binary: Callable[..., Path], BIN_NAME: str
    ) -> None:
        rule_text = """
        rule absent_string_no_match {
            strings:
                $a = "definitely_not_in_this_binary_xyz123"
            condition:
                $a
        }
        """

        result = ida_client.root.validate_yara_rule(rule_text=rule_text)

        assert result.success is False
        assert "did not match" in str(result.result)

    def test_rule_with_absent_bytes_fails_to_match(
        self,
        ida_client: rpyc.Connection,
    ) -> None:
        # A long, effectively-arbitrary byte sequence extremely unlikely to
        # occur anywhere in the binary.
        absent_chunk = bytes(range(0xE0, 0xF0))

        rule_text = f"""
        rule absent_bytes_no_match {{
            strings:
                $a = {_hex_pattern(absent_chunk)}
            condition:
                $a
        }}
        """

        result = ida_client.root.validate_yara_rule(rule_text=rule_text)

        assert result.success is False
        assert "did not match" in str(result.result)

    def test_malformed_rule_fails_to_compile(self, ida_client: rpyc.Connection) -> None:
        # Missing closing brace / invalid syntax.
        rule_text = 'rule broken_syntax { strings: $a = "foo" condition: $a'

        result = ida_client.root.validate_yara_rule(rule_text=rule_text)

        assert result.success is False

    def test_multiple_rules_in_single_input_are_rejected(self, ida_client: rpyc.Connection) -> None:
        rule_text = """
        rule first_rule { condition: true }
        rule second_rule { condition: true }
        """

        result = ida_client.root.validate_yara_rule(rule_text=rule_text)

        assert result.success is False

    def test_binary_data_is_read_from_currently_loaded_binary(
        self, ida_client: rpyc.Connection, get_binary: Callable[..., Path], BIN_NAME: str
    ) -> None:
        """Sanity check: validation reads bytes from IDA's loaded database,
        not from an arbitrary file, so results should be stable across
        repeated calls against the same session."""
        binary_path = get_binary(BIN_NAME)
        data = binary_path.read_bytes()
        chunk = data[0x20 : 0x20 + 8]

        rule_text = f"""
        rule repeatable_match {{
            strings:
                $a = {_hex_pattern(chunk)}
            condition:
                $a
        }}
        """

        first = ida_client.root.validate_yara_rule(rule_text=rule_text)
        second = ida_client.root.validate_yara_rule(rule_text=rule_text)

        assert first.success is True
        assert second.success is True
        assert first.result == second.result == "repeatable_match"
