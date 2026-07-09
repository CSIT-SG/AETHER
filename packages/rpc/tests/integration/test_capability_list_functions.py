# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="package")
@pytest.mark.order(after="test_connection.py::TestLiveCapabilities::test_connection_is_alive")
class TestGetFunctionByAddress:
    def test_finds_main(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_address(address="main")
        assert result.success is True
        assert result.result["name"] == "main"

    def test_finds_function_by_address_within_body(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="main")
        assert main_func.success is True

        inner_address = hex(int(main_func.result["start_address"], 16) + 1)
        result = ida_client.root.get_function_by_address(address=inner_address)
        assert result.success is True
        assert result.result["start_address"] == main_func.result["start_address"]

    def test_returns_none_for_bad_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_address(address="0xDEADBEEFDEADBEEF")
        assert result.success is False

    def test_returns_none_for_address_outside_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_address(address="0x0")
        assert result.success is False

    def test_metadata_shape(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_function_by_address(address="main")
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
