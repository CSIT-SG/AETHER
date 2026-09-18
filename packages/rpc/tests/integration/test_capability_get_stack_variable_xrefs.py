# type:ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetStackVariableXrefs:
    def test_get_xrefs_to_stack_variable(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_stack_variable_xrefs(
            function_location="foo_comment", local_variable_name="v4"
        )
        assert result.success is True
        assert result.result["stack_info"] is not None
        assert result.result["stack_info"]["xrefs"] is not None
        assert len(result.result["stack_info"]["xrefs"]) != 0

    def test_includes_xrefs_to_owning_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_stack_variable_xrefs(
            function_location="main", local_variable_name="v4"
        )
        comp = ida_client.root.get_function_by_name(function_name="main")
        assert result.success is True
        assert result.result["target_name"] == "main"
        assert result.result["target_address"] == comp.result["start_address"]
        assert result.result["xrefs"] is not None
        assert result.result["count"] != 0

    def test_stack_variable_name_does_not_corrupt(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_stack_variable_xrefs(
            function_location="main", local_variable_name="v4"
        )
        assert result.success is True
        assert result.result["stack_info"]["name"] is not None

    def test_stack_variable_xrefs_reference_owning_function(
        self, ida_client: rpyc.Connection
    ) -> None:
        result = ida_client.root.get_stack_variable_xrefs(
            function_location="main", local_variable_name="v4"
        )
        assert result.success is True
        stack_info = result.result["stack_info"]
        assert stack_info is not None
        for xref in stack_info["xrefs"]:
            assert xref["is_code"] is True
            assert xref["from_function"] is not None
            assert xref["from_function"]["name"] == "main"

    def test_return_none_for_invalid_stack_variable_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_stack_variable_xrefs(
            function_location="stack_var_target", local_variable_name="s;kjfhsdjksndkgn"
        )
        assert result.success is True
        assert result.result["stack_info"] is None

    def test_return_none_for_invalid_function_with_valid_variable_name(
        self, ida_client: rpyc.Connection
    ) -> None:
        result = ida_client.root.get_stack_variable_xrefs(
            function_location="s;kjfhsdjksndkgn", local_variable_name="v4"
        )
        assert result.success is False
