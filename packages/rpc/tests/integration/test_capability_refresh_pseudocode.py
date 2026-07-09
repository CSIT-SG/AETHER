# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestRefreshPseudocode:
    """Tests for refreshing the pseudocode view."""

    def test_refresh_by_name(self, ida_client: rpyc.Connection) -> None:
        # Accepts a function name and reports the resolved function start address.
        func = ida_client.root.get_function_by_name(function_name="main")
        assert func.success is True

        result = ida_client.root.refresh_pseudocode(function_address="main")
        assert result.success is True
        assert result.result == func.result["start_address"]

    def test_refresh_by_start_address(self, ida_client: rpyc.Connection) -> None:
        # Accepts a hex string address at the function start.
        func = ida_client.root.get_function_by_name(function_name="main")
        start_addr = func.result["start_address"]

        result = ida_client.root.refresh_pseudocode(function_address=start_addr)
        assert result.success is True
        assert result.result == start_addr

    def test_refresh_by_integer_address(self, ida_client: rpyc.Connection) -> None:
        # Accepts an integer address.
        func = ida_client.root.get_function_by_name(function_name="main")
        start_addr = func.result["start_address"]

        result = ida_client.root.refresh_pseudocode(function_address=int(start_addr, 16))
        assert result.success is True
        assert result.result == start_addr

    def test_refresh_by_address_within_function_body(self, ida_client: rpyc.Connection) -> None:
        # An address inside the function resolves back to the function start.
        func = ida_client.root.get_function_by_name(function_name="main")
        start_addr = func.result["start_address"]
        inner_address = hex(int(start_addr, 16) + 1)

        result = ida_client.root.refresh_pseudocode(function_address=inner_address)
        assert result.success is True
        assert result.result == start_addr

    def test_returns_false_for_invalid_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.refresh_pseudocode(function_address="0xDEADBEEFDEADBEEF")
        assert result.success is False

    def test_returns_false_for_address_outside_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.refresh_pseudocode(function_address="0x0")
        assert result.success is False
