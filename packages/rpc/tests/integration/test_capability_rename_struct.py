# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestRenameStruct:
    """Tests for valid and invalid struct rename requests."""

    def test_rename_struct_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_rename_struct_by_name",
            fields=[
                ("field", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.rename_struct(
            struct="test_rename_struct_by_name",
            new_name="renamed_struct",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["old_struct_name"] == "test_rename_struct_by_name"
        assert result.result["new_struct_name"] == "renamed_struct"

    def test_rename_struct_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_rename_struct_by_id",
            fields=[
                ("field", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.rename_struct(
            struct=created.result["struct_id"],
            new_name="renamed_struct_2",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["old_struct_name"] == "test_rename_struct_by_id"
        assert result.result["new_struct_name"] == "renamed_struct_2"

    def test_rename_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_struct(
            struct="idontexist_struct",
            new_name="renamed_struct",
        )

        assert result.success is False

    def test_rename_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.rename_struct(
            struct=99999999,
            new_name="renamed_struct",
        )

        assert result.success is False

    def test_rename_struct_to_invalid_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_rename_invalid_name",
            fields=[
                ("field", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.rename_struct(
            struct="test_rename_invalid_name",
            new_name="",
        )

        assert result.success is False

    def test_rename_struct_to_existing_name(self, ida_client: rpyc.Connection) -> None:
        first = ida_client.root.create_struct(
            struct_name="test_rename_existing_first",
            fields=[
                ("field", "uint32_t"),
            ],
        )
        assert first.success is True

        second = ida_client.root.create_struct(
            struct_name="test_rename_existing_second",
            fields=[
                ("field", "uint32_t"),
            ],
        )
        assert second.success is True

        result = ida_client.root.rename_struct(
            struct="test_rename_existing_first",
            new_name="test_rename_existing_second",
        )

        assert result.success is False
