# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestRenameFunction:
    def test_renames_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_function(
            address="foo_rename_func", new_name="AETHER_test_renamed_main"
        )
        assert result.success is True

        func = ida_client.root.get_function_by_name(function_name="AETHER_test_renamed_main")
        assert func.success is True
        assert "AETHER_test_renamed_main" in func.result["name"]

    def test_rename_is_reflected_by_address_lookup(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="AETHER_test_renamed_main")
        assert main_func.success is True

        func = ida_client.root.get_function_by_address(address=main_func.result["start_address"])
        assert func.success is True
        assert "AETHER_test_renamed_main" in func.result["name"]

    def test_accepts_integer_address(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="AETHER_test_renamed_main")
        assert main_func.success is True

        int_address = int(main_func.result["start_address"], 16)
        result = ida_client.root.rename_function(
            address=int_address, new_name="AETHER_test_int_addr_renamed"
        )
        assert result.success is True

    def test_accepts_address_within_function_body(self, ida_client: rpyc.Connection) -> None:
        main_func = ida_client.root.get_function_by_address(address="AETHER_test_int_addr_renamed")
        assert main_func.success is True

        inner_address = hex(int(main_func.result["start_address"], 16) + 1)
        result = ida_client.root.rename_function(
            address=inner_address, new_name="test_inner_renamed"
        )
        assert result.success is True

        func = ida_client.root.get_function_by_address(address=main_func.result["start_address"])
        assert func.success is True
        assert "test_inner_renamed" in func.result["name"]

    def test_returns_false_for_invalid_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_function(address="0xDEADBEEFDEADBEEF", new_name="test_bad")
        assert result.success is False

    def test_returns_false_for_address_outside_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_function(address="0x0", new_name="test_bad")
        assert result.success is False
