# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestApplyStruct:
    """Tests for valid and invalid apply struct requests."""

    def test_apply_struct_on_stack_variable(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="person",
            fields=[
                ("name", "char", 52),
                ("age", "int32_t"),
                ("height", "float"),
            ],
        )
        assert created.success is True

        result = ida_client.root.apply_struct(
            struct="person", function_name="struct_test", variable="v1"
        )

        assert result.success is True
        assert result.result["function_name"] == "struct_test"
        assert result.result["struct_id"] == created.result["struct_id"]
        assert result.result["struct_name"] == "person"
        assert result.result["variable"] == "v1"

    def test_apply_struct_on_global_variable(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="person", function_name="struct_test", variable="juliet"
        )

        address = ida_client.root.get_data_at_address(location="juliet").result["address"]

        assert result.success is True
        assert result.result["address"] == address
        assert result.result["struct_name"] == "person"

        info = ida_client.root.get_struct_info(
            struct="person",
        )

        assert info.success is True
        assert info.result["applied_to"][0] == address

    def test_apply_struct_on_pointer(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="person", function_name="struct_test", variable="var_8"
        )

        assert result.success is True
        assert result.result["function_name"] == "struct_test"
        assert result.result["struct_name"] == "person"
        assert result.result["variable"] == "var_8"

    def test_apply_struct_on_argument(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="person", function_name="print_person", variable="a1"
        )

        assert result.success is True
        assert result.result["function_name"] == "print_person"
        assert result.result["struct_name"] == "person"
        assert result.result["variable"] == "a1"

        lvars = ida_client.root.get_local_variables(function_name="print_person")
        a1 = next(var for var in lvars.result if var["name"] == "a1")

        # the argument is narrower than the struct, so it is retyped as a pointer
        assert a1["is_arg_var"]
        assert a1["type"] == "person *"

    def test_apply_struct_on_zero_offset_stack_member(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_apply_zero_offset",
            fields=[
                ("a", "uint32_t"),
                ("b", "uint32_t"),
            ],
        )
        assert created.success is True

        # var_20 sits at frame offset 0, which must not be read as "no offset"
        result = ida_client.root.apply_struct(
            struct="test_apply_zero_offset", function_name="im_orphaned", variable="var_20"
        )

        assert result.success is True
        assert result.result["function_name"] == "im_orphaned"
        assert result.result["struct_name"] == "test_apply_zero_offset"
        assert result.result["variable"] == "var_20"

    def test_apply_struct_on_register_variable(self, ida_client: rpyc.Connection) -> None:
        # v0 lives in a register, so it has no frame offset to lay the struct over
        result = ida_client.root.apply_struct(
            struct="person", function_name="pre_c_init", variable="v0"
        )

        assert result.success is False
        assert "not a stack variable" in result.result

    def test_apply_struct_too_big_for_stack(self, ida_client: rpyc.Connection) -> None:
        created = ida_client.root.create_struct(
            struct_name="test_apply_too_big",
            fields=[
                ("blob", "char", 4096),
            ],
        )
        assert created.success is True

        result = ida_client.root.apply_struct(
            struct="test_apply_too_big", function_name="qux_fill", variable="i"
        )

        assert result.success is False
        assert "too big" in result.result

    def test_apply_non_existent_struct(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="idontexist_struct", function_name="struct_test", variable="juliet"
        )

        assert result.success is False

    def test_apply_non_existent_struct_id(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct=99999999, function_name="struct_test", variable="juliet"
        )

        assert result.success is False

    def test_apply_struct_invalid_function(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="person", function_name="idontexist_func", variable="juliet"
        )

        assert result.success is False

    def test_apply_struct_invalid_variable(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.apply_struct(
            struct="person", function_name="struct_test", variable="idontexist_var"
        )

        assert result.success is False
