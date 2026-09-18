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

    def test_result_has_no_stack_info(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        assert result.success is True
        assert "stack_info" not in result.result
