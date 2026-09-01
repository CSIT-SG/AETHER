# type:ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetXrefsTo:
    def test_get_xrefs_to_main(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        assert result.success is True
        assert result.result["xrefs"] is not None
        assert result.result["count"] != 0

    def test_name_does_not_corrupt(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        assert result.success is True
        assert result.result["target_name"] == "main"

    def test_address_is_right(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        comp = ida_client.root.get_function_by_name(function_name="main")
        assert result.result["target_address"] == comp.result["start_address"]

    def test_return_none_for_gibberish_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="s;kjfhsdjksndkgn")
        assert result.success is False

    def test_finds_orphaned_func(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="im_orphaned")
        assert result.success is True
        assert result.result["xrefs"] is not None and result.result["count"] == 2


@pytest.mark.dependency(scope="package")
class TestGetXrefsToStackVariable:
    def test_get_xrefs_to_stack_variable(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="foo_comment", variable="v4")
        print(result.result)
        assert result.success is True
        assert result.result["xrefs"] is not None
        assert result.result["count"] != 0

    def test_stack_variable_name_does_not_corrupt(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main", variable="v4")
        assert result.success is True

    def test_stack_variable_xrefs_reference_owning_function(
        self, ida_client: rpyc.Connection
    ) -> None:
        result = ida_client.root.get_xrefs_to(location="main", variable="v4")
        assert result.success is True
        for xref in result.result["xrefs"]:
            assert xref["is_code"] is True
            assert xref["from_function"] is not None
            assert xref["from_function"]["name"] == "main"

    def test_return_none_for_invalid_stack_variable_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(
            location="stack_var_target", variable="s;kjfhsdjksndkgn"
        )
        assert result.success is False

    def test_return_none_for_invalid_function_with_valid_variable_name(
        self, ida_client: rpyc.Connection
    ) -> None:
        result = ida_client.root.get_xrefs_to(location="s;kjfhsdjksndkgn", variable="v4")
        assert result.success is False
