# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestRenameFunction:
    def test_renames_function(self, ida_client: rpyc.Connection) -> None:
        result= ida_client.root.rename_function(address="main", new_name="test_renamed_main")
        assert result is True

        func = ida_client.root.get_function_by_name(function_name="test_renamed_main")
        assert func is not None
        assert func["name"] == "test_renamed_main"

    def test_rename_is_reflected_by_address_lookup(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="main")
        assert main_func is not None

        result = ida_client.root.rename_function(address="main", new_name="test_addr_renamed")
        assert result is True

        func = ida_client.root.get_function_by_address(address=main_func["start_address"])
        assert func is not None
        assert func["name"] == "test_addr_renamed"

    def test_accepts_integer_address(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="main")
        assert main_func is not None

        int_address = int(main_func["start_address"], 16)
        result = ida_client.root.rename_function(address=int_address, new_name="test_int_addr_renamed")
        assert result is True

    def test_accepts_address_within_function_body(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="main")
        assert main_func is not None

        inner_address = hex(int(main_func["start_address"], 16) + 1)
        result = ida_client.root.rename_function(address=inner_address, new_name="test_inner_renamed")
        assert result is True

        func = ida_client.root.get_function_by_address(address=main_func["start_address"])
        assert func is not None
        assert func["name"] == "test_inner_renamed"

    def test_returns_false_for_invalid_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_function(address="0xDEADBEEFDEADBEEF", new_name="test_bad")
        assert result is False

    def test_returns_false_for_address_outside_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_function(address="0x0", new_name="test_bad")
        assert result is False
