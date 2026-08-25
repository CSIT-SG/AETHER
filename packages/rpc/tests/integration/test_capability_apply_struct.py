# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestApplyStruct:
    """Tests for valid and invalid apply struct requests."""

    def test_apply_struct_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_apply_struct_by_name",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        address = 0x140009150

        result = ida_client.root.apply_struct(
            struct="test_apply_struct_by_name",
            address=address,
        )

        assert result.success is True
        assert result.result["address"] == hex(address)
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_apply_struct_by_name"

        info = ida_client.root.get_struct_info(
            struct="test_apply_struct_by_name",
        )

        assert info.success is True
        assert info.result["applied_to"][0] == hex(address)
        assert info.result["struct_id"] == created.result["struct_id"]

    def test_apply_struct_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_apply_struct_by_id",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        address = 0x140009150

        result = ida_client.root.apply_struct(
            struct=created.result["struct_id"],
            address=address,
        )

        assert result.success is True
        assert result.result["address"] == hex(address)
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_apply_struct_by_id"

        info = ida_client.root.get_struct_info(
            struct="test_apply_struct_by_id",
        )

        assert info.success is True
        assert info.result["applied_to"][0] == hex(address)
        assert info.result["struct_id"] == created.result["struct_id"]

    def test_apply_non_existent_struct(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="idontexist_struct",
            address=0x140009150,
        )

        assert result.success is False

    def test_apply_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct=99999999,
            address=0x140009150,
        )

        assert result.success is False

    def test_apply_struct_invalid_address(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_apply_struct_invalid_address",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.apply_struct(
            struct="test_apply_struct_invalid_address",
            address=-1,
        )

        assert result.success is False
