import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestGetDataAtAddress:
    """Tests for valid address & symbol name provided and invalid address & symbol name provided"""
    def test_accept_valid_symbol_name(self, ida_client: rpyc.Connection) -> None:
        # Assert valid symbol name returns dict type
        data = ida_client.root.get_data_at_address(location="main")

        assert data is not None
        assert isinstance(data, (dict, rpyc.core.netref.BaseNetref))

        # Assert returned address correct/valid
        rtn_addr = ida_client.root.get_function_by_address(address=data["address"])

        assert rtn_addr is not None
        assert rtn_addr["name"] == "main"

    def test_accept_valid_address(self, ida_client: rpyc.Connection) -> None:
        # Assert valid address returns valid symbol name
        address = ida_client.root.get_function_by_name(function_name="main")
        assert address is not None

        data = ida_client.root.get_data_at_address(location=address["name"])

        assert data is not None
        assert data["name"] == "main"


    def test_non_existent_address(self, ida_client: rpyc.Connection) -> None:
        # Check address has no symbol name
        address = ida_client.root.get_function_by_address(address="0xB33F")

        assert address is None

        # Assert Invalid location returns None
        data = ida_client.root.get_data_at_address(location="0xB33F")

        assert data is None


    def test_non_existent_symbol_name(self, ida_client:rpyc.Connection) -> None:
        # Check symbol name does not exist
        func = ida_client.root.get_function_by_name(function_name="idontexistright")

        assert func is None

        # Assert Invalid Symbol Name returns None
        data = ida_client.root.get_data_at_address(location="idontexistright")

        assert data is None

