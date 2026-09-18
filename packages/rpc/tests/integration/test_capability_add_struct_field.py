# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestAddStructField:
    """Tests for valid and invalid struct field add requests."""

    def test_add_field_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_field_by_name",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_field_by_name",
            field_name="field2",
            field_type="uint16_t",
            offset=4,
            array_length=None,
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_add_field_by_name"
        assert result.result["field_name"] == "field2"

    def test_add_field_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_field_by_id",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct=created.result["struct_id"],
            field_name="field2",
            field_type="uint16_t",
            offset=4,
            array_length=None,
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_add_field_by_id"
        assert result.result["field_name"] == "field2"

    def test_add_array_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_array_field",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_array_field",
            field_name="array_field",
            field_type="uint8_t",
            offset=4,
            array_length=8,
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_add_array_field"
        assert result.result["field_name"] == "array_field"

    def test_add_field_before_existing_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_field_before",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_field_before",
            field_name="new_field",
            field_type="uint16_t",
            offset=0,
            array_length=None,
        )

        assert result.success is True

    def test_add_field_inside_existing_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_field_inside",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_field_inside",
            field_name="new_field",
            field_type="uint8_t",
            offset=2,
            array_length=None,
        )

        assert result.success is True

    def test_add_field_beyond_struct_size(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_field_beyond_size",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        # struct is 4 bytes wide, so offset 16 is past its end
        result = ida_client.root.add_struct_field(
            struct="test_add_field_beyond_size",
            field_name="far_field",
            field_type="uint16_t",
            offset=16,
            array_length=None,
        )

        assert result.success is True
        assert result.result["field_name"] == "far_field"

        info = ida_client.root.get_struct_info(struct="test_add_field_beyond_size")
        assert info.success is True

        fields = {field[0]: field for field in info.result["struct_fields"]}
        assert "far_field" in fields

        # the struct must have grown to place the new field at the requested offset
        assert fields["field1"][3] == 0
        assert fields["far_field"][3] == 16
        assert fields["far_field"][2] == 2

    def test_add_array_field_beyond_struct_size(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_array_beyond_size",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        # struct is 6 bytes wide, so offset 32 is past its end
        result = ida_client.root.add_struct_field(
            struct="test_add_array_beyond_size",
            field_name="far_array",
            field_type="uint8_t",
            offset=32,
            array_length=8,
        )

        assert result.success is True

        info = ida_client.root.get_struct_info(struct="test_add_array_beyond_size")
        assert info.success is True

        fields = {field[0]: field for field in info.result["struct_fields"]}
        assert "far_array" in fields

        assert fields["field1"][3] == 0
        assert fields["field2"][3] == 4
        assert fields["far_array"][3] == 32
        assert fields["far_array"][2] == 8

    def test_add_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.add_struct_field(
            struct="idontexist_struct",
            field_name="field",
            field_type="uint32_t",
            offset=0,
            array_length=None,
        )

        assert result.success is False

    def test_add_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.add_struct_field(
            struct=99999999,
            field_name="field",
            field_type="uint32_t",
            offset=0,
            array_length=None,
        )

        assert result.success is False

    def test_add_duplicate_field(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_duplicate_field",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_duplicate_field",
            field_name="field1",
            field_type="uint16_t",
            offset=4,
            array_length=None,
        )

        assert result.success is False

    def test_add_invalid_field_type(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_invalid_field_type",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_invalid_field_type",
            field_name="field2",
            field_type="invalid_type",
            offset=4,
            array_length=None,
        )

        assert result.success is False

    def test_add_zero_array_length(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_zero_array_length",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_zero_array_length",
            field_name="array_field",
            field_type="uint8_t",
            offset=4,
            array_length=0,
        )

        assert result.success is False

    def test_add_negative_array_length(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_negative_array_length",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_negative_array_length",
            field_name="array_field",
            field_type="uint8_t",
            offset=4,
            array_length=-1,
        )

        assert result.success is False

    def test_add_invalid_array_length(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_add_invalid_array_length",
            fields=[
                ("field1", "uint32_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.add_struct_field(
            struct="test_add_invalid_array_length",
            field_name="array_field",
            field_type="uint8_t",
            offset=4,
            array_length="invalid",
        )

        assert result.success is False
