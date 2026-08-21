# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestChangeStructFieldType:
    """Tests for valid and invalid struct field type change requests."""

    def test_change_field_type_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_field_type_by_name",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct="test_change_field_type_by_name",
            field_name="field1",
            new_type="uint64_t",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_change_field_type_by_name"
        assert result.result["field_name"] == "field1"
        assert result.result["new_type"] == "uint64_t"

    def test_change_field_type_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_field_type_by_id",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct=created.result["struct_id"],
            field_name="field1",
            new_type="uint64_t",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_change_field_type_by_id"
        assert result.result["field_name"] == "field1"
        assert result.result["new_type"] == "uint64_t"

    def test_change_field_type_to_smaller_type(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_field_type_smaller",
            fields=[
                ("field1", "uint64_t"),
                ("field2", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct="test_change_field_type_smaller",
            field_name="field1",
            new_type="uint32_t",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["field_name"] == "field1"
        assert result.result["new_type"] == "uint32_t"

    def test_change_field_type_to_larger_type(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_field_type_larger",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct="test_change_field_type_larger",
            field_name="field1",
            new_type="uint64_t",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["field_name"] == "field1"
        assert result.result["new_type"] == "uint64_t"

        result = ida_client.root.get_struct_info(
            struct="test_change_field_type_larger",
        )

        assert result.success is True
        # Check if next field shifted right
        assert result.result["struct_fields"][1][0] == "field2"
        assert result.result["struct_fields"][1][3] == 8

    def test_change_field_type_to_named_type(self, ida_client: rpyc.Connection) -> None:
        type_struct = ida_client.root.create_struct(
            struct_name="test_change_field_type_named_type",
            fields=[
                ("value", "uint32_t"),
            ],
        )
        assert type_struct.success is True

        created = ida_client.root.create_struct(
            struct_name="test_change_field_type_target",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct="test_change_field_type_target",
            field_name="field1",
            new_type="test_change_field_type_named_type",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_change_field_type_target"
        assert result.result["field_name"] == "field1"
        assert result.result["new_type"] == "test_change_field_type_named_type"

    def test_change_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.change_struct_field_type(
            struct="idontexist_struct",
            field_name="field",
            new_type="uint64_t",
        )

        assert result.success is False

    def test_change_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.change_struct_field_type(
            struct=99999999,
            field_name="field",
            new_type="uint64_t",
        )

        assert result.success is False

    def test_change_non_existent_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_missing_field",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct="test_change_missing_field",
            field_name="does_not_exist",
            new_type="uint64_t",
        )

        assert result.success is False

    def test_change_to_invalid_type(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_change_invalid_type",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.change_struct_field_type(
            struct="test_change_invalid_type",
            field_name="field1",
            new_type="invalid_type",
        )

        assert result.success is False
