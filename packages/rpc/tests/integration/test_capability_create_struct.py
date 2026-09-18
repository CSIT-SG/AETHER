# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestCreateStruct:
    """Tests for valid and invalid struct creation requests."""

    def test_create_empty_struct(self, ida_client: rpyc.Connection) -> None:
        struct = ida_client.root.create_struct(struct_name="test_empty_struct")

        assert struct.success is True
        assert struct.result["struct_id"] > 0
        assert struct.result["struct_name"] == "test_empty_struct"

    def test_create_struct_with_fields(self, ida_client: rpyc.Connection) -> None:
        fields = [
            ("id", "uint32_t"),
            ("name", "char", 32),
            ("flags", "uint16_t"),
        ]

        struct = ida_client.root.create_struct(
            struct_name="test_struct_with_fields",
            fields=fields,
        )

        assert struct.success is True
        assert struct.result["struct_id"] > 0
        assert struct.result["struct_name"] == "test_struct_with_fields"

    def test_reject_invalid_field_type(self, ida_client: rpyc.Connection) -> None:
        fields = [
            ("id", "not_a_real_type"),
        ]

        struct = ida_client.root.create_struct(
            struct_name="test_invalid_type",
            fields=fields,
        )

        assert struct.success is False

    def test_reject_invalid_fields_type(self, ida_client: rpyc.Connection) -> None:
        struct = ida_client.root.create_struct(
            struct_name="test_invalid_fields",
            fields="not_a_list",
        )

        assert struct.success is False

    def test_reject_invalid_field_length(self, ida_client: rpyc.Connection) -> None:
        fields = [
            ("field",),
        ]

        struct = ida_client.root.create_struct(
            struct_name="test_invalid_field_length",
            fields=fields,
        )

        assert struct.success is False

    def test_reject_malformed_field(self, ida_client: rpyc.Connection) -> None:
        fields = [
            (123, "uint32_t"),
        ]

        struct = ida_client.root.create_struct(
            struct_name="test_malformed_field",
            fields=fields,
        )

        assert struct.success is False

    def test_reject_invalid_array_length(self, ida_client: rpyc.Connection) -> None:
        fields = [
            ("name", "char", "32"),
        ]

        struct = ida_client.root.create_struct(
            struct_name="test_invalid_array_length",
            fields=fields,
        )

        assert struct.success is False
