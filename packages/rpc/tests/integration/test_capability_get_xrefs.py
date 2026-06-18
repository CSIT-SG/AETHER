# type:ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestGetXrefsTo:
    def test_get_xrefs_to_main(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        assert result["xrefs"] is not None
        assert result["count"] != 0

    def test_name_does_not_corrupt(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        assert result["target_name"] == "main"

    def test_address_is_right(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="main")
        comp = ida_client.root.get_function_by_name(function_name="main")
        assert result["target_address"] == comp["start_address"]

    def test_return_none_for_gibberish_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_xrefs_to(location="s;kjfhsdjksndkgn")
        assert result is None
