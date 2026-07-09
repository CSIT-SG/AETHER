# type:ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetLocalVariables:
    def test_returns_local_variables_for_main(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_local_variables(function_name="main")
        assert result.success is True
        assert len(result.result) > 0

    def test_metadata_shape(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_local_variables(function_name="main")
        assert result.success is True
        for var in result.result:
            assert "name" in var
            assert "type" in var
            assert "is_arg_var" in var
            assert "is_stk_var" in var
            assert "is_reg_var" in var
            assert isinstance(var["name"], str)

    def test_returns_none_for_unknown_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_local_variables(function_name="__nonexistent_symbol__")
        assert result.success is False

    def test_returns_none_for_empty_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_local_variables(function_name="")
        assert result.success is False

    def test_result_matches_rename_local_variable_targets(
        self, ida_client: rpyc.Connection
    ) -> None:
        """Variable names returned should be valid targets for rename_local_variable."""
        lvars = ida_client.root.get_local_variables(function_name="main")
        assert lvars.success is True
        assert len(lvars.result) > 0

        original_name = lvars.result[0]["name"]
        result = ida_client.root.rename_local_variable(
            function_address="main",
            old_var_name=original_name,
            new_var_name="test_cross_capability_var",
        )
        assert result.success is True
