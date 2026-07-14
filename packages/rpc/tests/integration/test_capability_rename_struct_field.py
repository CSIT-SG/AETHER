# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestRenameStructField:
    """Tests for valid and invalid struct field rename requests."""

    def test_rename_field_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_rename_field_by_name",
            fields=[
                ("old_field", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.rename_struct_field(
            struct="test_rename_field_by_name",
            old_field_name="old_field",
            new_field_name="new_field",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_rename_field_by_name"
        assert result.result["old_field_name"] == "old_field"
        assert result.result["new_field_name"] == "new_field"

    def test_rename_field_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_rename_field_by_id",
            fields=[
                ("old_field", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.rename_struct_field(
            struct=created.result["struct_id"],
            old_field_name="old_field",
            new_field_name="new_field",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_rename_field_by_id"
        assert result.result["old_field_name"] == "old_field"
        assert result.result["new_field_name"] == "new_field"

    def test_rename_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_struct_field(
            struct="idontexist_struct",
            old_field_name="field",
            new_field_name="renamed",
        )

        assert result.success is False

    def test_rename_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_struct_field(
            struct=99999999,
            old_field_name="field",
            new_field_name="renamed",
        )

        assert result.success is False

    def test_rename_non_existent_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_rename_missing_field",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.rename_struct_field(
            struct="test_rename_missing_field",
            old_field_name="does_not_exist",
            new_field_name="new_field",
        )

        assert result.success is False
