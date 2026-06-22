# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestGetDataAtAddress:
    """Tests for valid address & symbol name provided and invalid address & symbol name provided"""

    def test_accept_valid_symbol_name(self, ida_client: rpyc.Connection) -> None:
        # Assert valid symbol name returns dict type
        data = ida_client.root.get_data_at_address(location="main")

        assert data.success is True
        assert data.result["item_size"] > 0
        assert data.result["raw_bytes"] is not None
        assert data.result["name"] == "main"

        # Assert returned address correct/valid
        rtn_addr = ida_client.root.get_function_by_address(address=data.result["address"])

        assert rtn_addr.success is True
        assert rtn_addr.result["name"] == "main"

    def test_accept_valid_address(self, ida_client: rpyc.Connection) -> None:
        # Assert valid address returns valid symbol name
        address = ida_client.root.get_function_by_name(function_name="main")
        assert address.success is True

        data = ida_client.root.get_data_at_address(location=address.result["name"])

        assert data.success is True
        assert data.result["name"] == "main"

    def test_non_existent_address(self, ida_client: rpyc.Connection) -> None:
        # Check address has no symbol name
        address = ida_client.root.get_function_by_address(address="0xB33F")

        assert address.success is False

        # Assert Invalid location returns failure
        data = ida_client.root.get_data_at_address(location="0xB33F")

        assert data.success is False

    def test_non_existent_symbol_name(self, ida_client: rpyc.Connection) -> None:
        # Check symbol name does not exist
        func = ida_client.root.get_function_by_name(function_name="idontexistright")

        assert func.success is False

        # Assert Invalid Symbol Name returns failure
        data = ida_client.root.get_data_at_address(location="idontexistright")

        assert data.success is False
