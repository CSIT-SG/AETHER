# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetStructInfo:
    """Tests for valid and invalid struct info requests."""

    def test_get_struct_info_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_get_struct_info_by_name",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.get_struct_info(
            struct="test_get_struct_info_by_name",
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_get_struct_info_by_name"
        assert len(result.result["struct_fields"]) == 2

        assert result.result["struct_fields"][0][0] == "field1"
        assert result.result["struct_fields"][0][1] == "unsigned __int32"
        assert result.result["struct_fields"][0][2] == 4
        assert result.result["struct_fields"][0][3] == 0

        assert result.result["struct_fields"][1][0] == "field2"
        assert result.result["struct_fields"][1][1] == "unsigned __int16"
        assert result.result["struct_fields"][1][2] == 2
        assert result.result["struct_fields"][1][3] == 4

    def test_get_struct_info_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_get_struct_info_by_id",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.get_struct_info(
            struct=created.result["struct_id"],
        )

        assert result.success is True
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "test_get_struct_info_by_id"
        assert len(result.result["struct_fields"]) == 2

        assert result.result["struct_fields"][0][0] == "field1"
        assert result.result["struct_fields"][0][1] == "unsigned __int32"
        assert result.result["struct_fields"][0][2] == 4
        assert result.result["struct_fields"][0][3] == 0

        assert result.result["struct_fields"][1][0] == "field2"
        assert result.result["struct_fields"][1][1] == "unsigned __int16"
        assert result.result["struct_fields"][1][2] == 2
        assert result.result["struct_fields"][1][3] == 4

    def test_get_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_struct_info(
            struct="idontexist_struct",
        )

        assert result.success is False

    def test_get_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_struct_info(
            struct=99999999,
        )

        assert result.success is False

    def test_get_struct_info_no_fields(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_get_struct_info_no_fields",
            fields=[],
        )
        assert created.success is True

        result = ida_client.root.get_struct_info(
            struct="test_get_struct_info_no_fields",
        )

        assert result.success is False
        assert result.result == "Struct test_get_struct_info_no_fields has no fields."
