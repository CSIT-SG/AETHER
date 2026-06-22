# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestSetComment:
    """Testing SetComment Uses Separate custom function 'foo_comment' to avoid clashing with other test cases"""

    def test_set_header_comment(self, ida_client: rpyc.Connection) -> None:
        # Assert comment set at function header (start_ea)
        data = ida_client.root.get_function_by_name(function_name="foo_comment")
        start_addr = data.result["start_address"]
        success = ida_client.root.set_comment(address=f"{start_addr}", comment="balls")

        assert success.success is True

        data = ida_client.root.get_function_pseudocode(function_name="foo_comment")
        pseudo = data.result["pseudocode"]

        assert "balls" in pseudo

    def test_set_pseudo_comment(self, ida_client: rpyc.Connection) -> None:
        # Assert comment set inside function (ea)
        # Get middle addr of function
        data = ida_client.root.get_function_by_name(function_name="foo_comment")
        start_addr = data.result["start_address"]
        end_addr = data.result["end_address"]
        middle_addr = int(start_addr, 16) + ((int(end_addr, 16) - int(start_addr, 16)) / 2)
        success = ida_client.root.set_comment(address=f"{middle_addr}", comment="smth like this")

        assert success.success is True

        data = ida_client.root.get_function_pseudocode(function_name="foo_comment")
        pseudo = data.result["pseudocode"]

        assert "smth like this" in pseudo
