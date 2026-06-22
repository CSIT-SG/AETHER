# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestGetFunctionByName:
    def test_finds_main_by_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="main")
        assert result.success is True
        assert result.result["name"] == "main"

    def test_returns_none_for_unknown_symbol(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="__nonexistent_symbol__")
        assert result.success is False

    def test_returns_none_for_empty_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="")
        assert result.success is False

    def test_metadata_shape(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="main")
        assert result.success is True
        assert "name" in result.result
        assert "start_address" in result.result
        assert "end_address" in result.result
        assert "size_bytes" in result.result
        assert "flags" in result.result
        start = int(result.result["start_address"], 16)
        end = int(result.result["end_address"], 16)
        assert result.result["size_bytes"] == end - start
        assert result.result["size_bytes"] > 0

    def test_result_matches_get_function_by_address(self, ida_client: rpyc.Connection) -> None:
        by_name = ida_client.root.get_function_by_name(function_name="main")
        assert by_name.success is True

        by_address = ida_client.root.get_function_by_address(address="main")
        assert by_address.success is True
        assert by_name.result["name"] == by_address.result["name"]
        assert by_name.result["start_address"] == by_address.result["start_address"]
        assert by_name.result["end_address"] == by_address.result["end_address"]
        assert by_name.result["size_bytes"] == by_address.result["size_bytes"]
