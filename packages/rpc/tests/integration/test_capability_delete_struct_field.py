# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestDeleteStructField:
    """Tests for valid and invalid struct field delete requests."""

    def test_delete_field_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_delete_field_by_name",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.delete_struct_field(
            struct="test_delete_field_by_name",
            field_name="field1",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_delete_field_by_name"
        assert result.result["field_name"] == "field1"

    def test_delete_field_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_delete_field_by_id",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.delete_struct_field(
            struct=created.result["struct_id"],
            field_name="field1",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_delete_field_by_id"
        assert result.result["field_name"] == "field1"

    def test_delete_middle_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_delete_middle_field",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
                ("field3", "uint8_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.delete_struct_field(
            struct="test_delete_middle_field",
            field_name="field2",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_delete_middle_field"
        assert result.result["field_name"] == "field2"

        result = ida_client.root.get_struct_info(
            struct="test_delete_middle_field",
        )

        assert result.success is True
        # Check if shift left
        assert result.result["struct_fields"][1][0] == "field3"
        assert result.result["struct_fields"][1][3] == 4

    def test_delete_last_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_delete_last_field",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.delete_struct_field(
            struct="test_delete_last_field",
            field_name="field2",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_delete_last_field"
        assert result.result["field_name"] == "field2"

    def test_delete_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.delete_struct_field(
            struct="idontexist_struct",
            field_name="field",
        )

        assert result.success is False

    def test_delete_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.delete_struct_field(
            struct=99999999,
            field_name="field",
        )

        assert result.success is False

    def test_delete_non_existent_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_delete_missing_field",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.delete_struct_field(
            struct="test_delete_missing_field",
            field_name="does_not_exist",
        )

        assert result.success is False
