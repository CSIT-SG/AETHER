# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetStructAtAddress:
    """Tests for getting a struct applied at an address."""

    def test_get_struct_at_address(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_get_struct_at_address",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        address = 0x140009150

        applied = ida_client.root.apply_struct(
            struct="test_get_struct_at_address",
            address=address,
        )
        assert applied.success is True

        result = ida_client.root.get_struct_at_address(
            address=address,
        )

        assert result.success is True
        assert result.result["address"] == hex(address)
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_get_struct_at_address"

    def test_get_struct_at_address_by_string(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_get_struct_at_address_string",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        address = "0x140009170"

        applied = ida_client.root.apply_struct(
            struct="test_get_struct_at_address_string",
            address=address,
        )
        assert applied.success is True

        result = ida_client.root.get_struct_at_address(
            address=address,
        )

        assert result.success is True
        assert result.result["address"] == hex(int(address, 16))
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_get_struct_at_address_string"

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
