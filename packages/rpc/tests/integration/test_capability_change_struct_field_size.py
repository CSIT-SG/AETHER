# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestChangeStructFieldSize:
    """Tests for valid and invalid struct field size change requests."""

    def test_change_field_size_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_field_size_by_name",
            fields=[
                ("buffer", "char", 8),
                ("value", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_size(
            struct="test_change_field_size_by_name",
            field_name="buffer",
            new_size="16",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_change_field_size_by_name"
        assert result.result["field_name"] == "buffer"
        assert result.result["new_size"] == "16"

    def test_change_field_size_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_field_size_by_id",
            fields=[
                ("buffer", "char", 4),
                ("value", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_size(
            struct=created.result["struct_id"],
            field_name="buffer",
            new_size="32",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_change_field_size_by_id"
        assert result.result["field_name"] == "buffer"
        assert result.result["new_size"] == "32"

    def test_change_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.change_struct_field_size(
            struct="idontexist_struct",
            field_name="buffer",
            new_size="16",
        )

        assert result.success is False

    def test_change_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.change_struct_field_size(
            struct=99999999,
            field_name="buffer",
            new_size="16",
        )

        assert result.success is False

    def test_change_non_existent_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_missing_field",
            fields=[
                ("buffer", "char", 8),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_size(
            struct="test_change_missing_field",
            field_name="does_not_exist",
            new_size="16",
        )

        assert result.success is False

    def test_change_field_size_invalid_size(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_invalid_size",
            fields=[
                ("buffer", "char", 8),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_size(
            struct="test_change_invalid_size",
            field_name="buffer",
            new_size="invalid",
        )

        assert result.success is False
