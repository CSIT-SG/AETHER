# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetStructAtAddress:
    """Tests for getting a struct applied at an address."""

    def test_get_struct_at_address(self, ida_client: rpyc.Connection) -> None:
        address = ida_client.root.get_data_at_address(location="juliet").result["address"]

        result = ida_client.root.get_struct_at_address(
            address=int(address, 16),
        )

        assert result.success is True
        assert result.result["address"] == address
        assert result.result["struct_name"] == "person"

    def test_get_struct_at_address_by_string(self, ida_client: rpyc.Connection) -> None:
        address = ida_client.root.get_data_at_address(location="juliet").result["address"]

        result = ida_client.root.get_struct_at_address(
            address="juliet",
        )

        assert result.success is True
        assert result.result["address"] == address
        assert result.result["struct_name"] == "person"

    def test_get_struct_at_address_without_struct(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_struct_at_address(
            address=0x140009190,
        )

        assert result.success is False

    def test_get_struct_at_invalid_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_struct_at_address(
            address=-1,
        )

        assert result.success is False
