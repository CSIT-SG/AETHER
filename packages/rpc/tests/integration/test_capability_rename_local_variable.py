# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="package")
@pytest.mark.order(after="test_connection.py::TestLiveCapabilities::test_connection_is_alive")
class TestRenameLocalVariable:
    def test_renames_local_variable(self, ida_client: rpyc.Connection) -> None:
        func = ida_client.root.get_function_by_name(function_name="main")
        assert func.success is True

        lvars = ida_client.root.get_local_variables(function_name="main")
        assert lvars.success is True
        assert len(lvars.result) > 0

        original_name = lvars.result[0]["name"]
        result = ida_client.root.rename_local_variable(
            function_address="main",
            old_var_name=original_name,
            new_var_name="test_renamed_var",
        )
        assert result.success is True

        lvars_after = ida_client.root.get_local_variables(function_name="main")
        names_after = [v["name"] for v in lvars_after.result]
        assert "test_renamed_var" in names_after
        assert original_name not in names_after

    def test_rename_is_reflected_in_decompilation(self, ida_client: rpyc.Connection) -> None:
        lvars = ida_client.root.get_local_variables(function_name="main")
        assert lvars.success is True
        assert len(lvars.result) > 0

        original_name = lvars.result[0]["name"]
        result = ida_client.root.rename_local_variable(
            function_address="main",
            old_var_name=original_name,
            new_var_name="test_decompile_var",
        )
        assert result.success is True

        lvars_after = ida_client.root.get_local_variables(function_name="main")
        names_after = [v["name"] for v in lvars_after.result]
        assert "test_decompile_var" in names_after

    def test_accepts_integer_address(self, ida_client: rpyc.Connection) -> None:
        func = ida_client.root.get_function_by_name(function_name="main")
        assert func.success is True

        lvars = ida_client.root.get_local_variables(function_name="main")
        assert lvars.success is True
        assert len(lvars.result) > 0

        int_address = int(func.result["start_address"], 16)
        original_name = lvars.result[0]["name"]
        result = ida_client.root.rename_local_variable(
            function_address=int_address,
            old_var_name=original_name,
            new_var_name="test_int_addr_var",
        )
        assert result.success is True

    def test_accepts_address_within_function_body(self, ida_client: rpyc.Connection) -> None:
        func = ida_client.root.get_function_by_name(function_name="main")
        assert func.success is True

        lvars = ida_client.root.get_local_variables(function_name="main")
        assert lvars.success is True
        assert len(lvars.result) > 0

        inner_address = hex(int(func.result["start_address"], 16) + 1)
        original_name = lvars.result[0]["name"]
        result = ida_client.root.rename_local_variable(
            function_address=inner_address,
            old_var_name=original_name,
            new_var_name="test_inner_addr_var",
        )
        assert result.success is True

    def test_returns_false_for_invalid_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_local_variable(
            function_address="0xDEADBEEFDEADBEEF",
            old_var_name="var_1",
            new_var_name="test_bad",
        )
        assert result.success is False

    def test_returns_false_for_address_outside_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_local_variable(
            function_address="0x0",
            old_var_name="var_1",
            new_var_name="test_bad",
        )
        assert result.success is False

    def test_returns_false_for_nonexistent_variable(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_local_variable(
            function_address="main",
            old_var_name="__nonexistent_var__",
            new_var_name="test_bad",
        )
        assert result.success is False
