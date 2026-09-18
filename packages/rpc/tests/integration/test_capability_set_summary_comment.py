# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestSetSummaryComment:
    """Testing SetSummaryComment Uses Separate custom function 'foo_comment' to avoid clashing with other test cases"""

    def test_set_header_comment(self, ida_client: rpyc.Connection) -> None:
        # Assert comment set at function header (start_ea)
        data = ida_client.root.get_function_by_name(function_name="foo_comment")
        start_addr = data.result["start_address"]
        success = ida_client.root.set_summary_comment(address=f"{start_addr}", comment="balls")

        assert success.success is True

        data = ida_client.root.get_function_pseudocode(function_name="foo_comment")
        pseudo = data.result["pseudocode"]

        assert "balls" in pseudo

    def test_set_header_comment_in_shellcode_throws_error(
        self, ida_client: rpyc.Connection
    ) -> None:
        # Assert comment set at function header (start_ea)
        addr = ida_client.root.get_data_at_address(location="test_shellcode")
        if not addr.success:
            raise RuntimeError(f"Failed to get address of test_shellcode: {addr.result}")
        success = ida_client.root.set_summary_comment(
            address=f"{addr.result['address']}", comment="shell_balls"
        )

        assert success.success is False
