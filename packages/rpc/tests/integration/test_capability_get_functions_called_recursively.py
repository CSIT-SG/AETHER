# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestGetFunctionsCalledRecursively:
    """Tests for get_functions_called_recursively capability."""

    def test_accept_valid_symbol_name(self, ida_client: rpyc.Connection) -> None:
        # Call capability using a valid function name
        result = ida_client.root.get_functions_called_recursively(address="main")

        assert result.success is True
        assert result.result["count"] >= 1
        assert len(result.result["functions"]) >= 1

        # First function should be the starting function
        first_function = result.result["functions"][0]
        assert first_function["function_name"] == "main"

        # Verify returned function address resolves correctly
        resolved = ida_client.root.get_function_by_address(address=first_function["address"])

        assert resolved.success is True
        assert resolved.result["name"] == "main"

    def test_accept_valid_address(self, ida_client: rpyc.Connection) -> None:
        # Get address of main
        func = ida_client.root.get_function_by_name(function_name="main")
        assert func.success is True

        # Call capability using address
        result = ida_client.root.get_functions_called_recursively(
            address=func.result["start_address"]
        )

        assert result.success is True
        assert result.result["count"] >= 1

        # Ensure the starting function is included
        first_function = result.result["functions"][0]
        assert first_function["function_name"] == "main"

    def test_returns_valid_function_entries(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="main")

        assert result.success is True

        for function in result.result["functions"]:
            assert "function_name" in function
            assert "address" in function
            assert function["function_name"] is not None

            # Every returned address should correspond to a valid function
            resolved = ida_client.root.get_function_by_address(address=function["address"])

            assert resolved.success is True
            assert resolved.result["name"] == function["function_name"]

    def test_non_existent_address(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="0xB33F")

        assert result.success is False

    def test_non_existent_symbol_name(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="idontexistright")

        assert result.success is False

    def test_max_depth(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="max_depth_call")

        assert result.success is True
        assert result.result["count"] == 6
        assert len(result.result["functions"]) == 6

    def test_self_call(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="self_call")

        assert result.success is True
        assert result.result["count"] == 1
        assert len(result.result["functions"]) == 1

    def test_parent(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="max_depth_call")

        for i in range(1, 6):
            assert (
                result.result["functions"][-i]["parent"]
                == result.result["functions"][-i - 1]["address"]
            )
