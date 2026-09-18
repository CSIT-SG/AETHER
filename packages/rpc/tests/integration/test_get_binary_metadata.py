# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetBinaryMetadata:
    def test_file_identity(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_binary_metadata()
        assert result.success is True

        metadata = result.result
        assert "basic" in metadata["file_name"].lower()
        assert metadata["file_path"] != ""
        assert metadata["file_size"] > 0

    def test_contains_a_code_section(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_binary_metadata()
        assert result.success is True

        sections = result.result["sections"]
        code_sections = [s for s in sections if "X" in s["perms"]]
        assert len(code_sections) > 0, "expected at least one executable section (e.g. .text)"

    def test_entry_point_falls_within_a_section(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_binary_metadata()
        assert result.success is True

        metadata = result.result
        entry_addr = int(metadata["entry_point"], 16)

        containing = [
            s for s in metadata["sections"] if int(s["start"], 16) <= entry_addr < int(s["end"], 16)
        ]
        assert len(containing) == 1, "entry point should land inside exactly one section"

    def test_entry_point_is_executable_code(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_binary_metadata()
        assert result.success is True

        metadata = result.result
        entry_addr = int(metadata["entry_point"], 16)

        containing = next(
            s for s in metadata["sections"] if int(s["start"], 16) <= entry_addr < int(s["end"], 16)
        )
        assert "X" in containing["perms"]

    def test_metadata_agrees_with_main_function(self, ida_client: rpyc.Connection) -> None:
        """Cross-check: main() should live inside the binary's addressable range."""
        metadata_result = ida_client.root.get_binary_metadata()
        assert metadata_result.success is True

        main_result = ida_client.root.get_function_by_address(address="main")
        assert main_result.success is True

        main_start = int(main_result.result["start_address"], 16)
        sections = metadata_result.result["sections"]

        containing = [s for s in sections if int(s["start"], 16) <= main_start < int(s["end"], 16)]
        assert len(containing) == 1
        assert "X" in containing[0]["perms"]
