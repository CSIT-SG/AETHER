# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestGetStructIdByName:
    """Tests for valid and invalid struct name lookups."""

    def test_get_existing_struct_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(struct_name="test_get_struct_id")

        assert created.success is True

        struct = ida_client.root.get_struct_id_by_name(struct_name="test_get_struct_id")

        assert struct.success is True
        assert struct.result == created.result["struct_id"]

    def test_get_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        struct = ida_client.root.get_struct_id_by_name(struct_name="idontexist_struct")

        assert struct.success is False
