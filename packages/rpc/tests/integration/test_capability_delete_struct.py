# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestDeleteStruct:
    """Tests for valid and invalid struct deletion requests."""

    def test_delete_struct_by_name(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(struct_name="test_delete_by_name")
        assert created.success is True

        deleted = ida_client.root.delete_struct(struct="test_delete_by_name")

        assert deleted.success is True
        assert deleted.result["struct_id"] == created.result["struct_id"]
        assert deleted.result["struct_name"] == "test_delete_by_name"

    def test_delete_struct_by_id(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(struct_name="test_delete_by_id")
        assert created.success is True

        deleted = ida_client.root.delete_struct(
            struct=created.result["struct_id"],
        )

        assert deleted.success is True
        assert deleted.result["struct_id"] == created.result["struct_id"]
        assert deleted.result["struct_name"] == "test_delete_by_id"

    def test_delete_non_existent_struct_name(self, ida_client: rpyc.Connection) -> None:
        deleted = ida_client.root.delete_struct(
            struct="idontexist_struct",
        )

        assert deleted.success is False

    def test_delete_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        deleted = ida_client.root.delete_struct(
            struct=99999999,
        )

        assert deleted.success is False

    def test_delete_struct_twice(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(struct_name="test_delete_twice")
        assert created.success is True

        first = ida_client.root.delete_struct(
            struct="test_delete_twice",
        )
        assert first.success is True

        second = ida_client.root.delete_struct(
            struct="test_delete_twice",
        )

        assert second.success is False
