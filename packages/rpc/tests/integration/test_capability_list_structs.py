# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestListStructs:
    """Tests for valid list structs requests."""

    def test_list_structs(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.list_structs()

        assert result.success is True

        before = result.result["number_of_structs"]

        created = ida_client.root.create_struct(
            struct_name="test_list_structs",
            fields=[
                ("field1", "uint32_t"),
                ("field2", "uint16_t"),
            ],
        )
        assert created.success is True

        result = ida_client.root.list_structs()

        assert result.success is True
        assert result.result["number_of_structs"] == before + 1

        struct = result.result["structs"][-1]

        assert struct["struct_id"] == created.result["struct_id"]
        assert struct["struct_name"] == "test_list_structs"
        assert len(struct["struct_fields"]) == 2

        assert struct["struct_fields"][0][0] == "field1"
        assert struct["struct_fields"][0][1] == "uint32_t"
        assert struct["struct_fields"][0][2] == 4
        assert struct["struct_fields"][0][3] == 0

        assert struct["struct_fields"][1][0] == "field2"
        assert struct["struct_fields"][1][1] == "uint16_t"
        assert struct["struct_fields"][1][2] == 2
        assert struct["struct_fields"][1][3] == 4
