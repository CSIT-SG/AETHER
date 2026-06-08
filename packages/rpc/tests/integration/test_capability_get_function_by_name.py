# type: ignore
import rpyc


class TestLiveCapabilities:
    def test_connection_is_alive(self, ida_client: rpyc.Connection) -> None:
        assert ida_client.root is not None


class TestGetFunctionByName:
    def test_finds_main_by_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="main")
        assert result is not None
        assert result["name"] == "main"

    def test_returns_none_for_unknown_symbol(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="__nonexistent_symbol__")
        assert result is None

    def test_returns_none_for_empty_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="")
        assert result is None

    def test_metadata_shape(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_name(function_name="main")
        assert result is not None
        assert "name" in result
        assert "start_address" in result
        assert "end_address" in result
        assert "size_bytes" in result
        assert "flags" in result
        start = int(result["start_address"], 16)
        end = int(result["end_address"], 16)
        assert result["size_bytes"] == end - start
        assert result["size_bytes"] > 0

    def test_result_matches_get_function_by_address(self, ida_client: rpyc.Connection) -> None:
        by_name = ida_client.root.get_function_by_name(function_name="main")
        assert by_name is not None

        by_address = ida_client.root.get_function_by_address(address="main")
        assert by_address is not None
        assert by_name["name"] == by_address["name"]
        assert by_name["start_address"] == by_address["start_address"]
        assert by_name["end_address"] == by_address["end_address"]
        assert by_name["size_bytes"] == by_address["size_bytes"]
