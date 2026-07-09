# type: ignore
import pytest
import rpyc


def count_nodes(node: dict) -> int:
    return 1 + sum(count_nodes(child) for child in node["children"])


@pytest.mark.dependency(depends=["connection"], scope="package")
@pytest.mark.order(after="test_connection.py::TestLiveCapabilities::test_connection_is_alive")
class TestGetFunctionsCalledRecursively:
    """Tests for get_functions_called_recursively capability."""

    def test_accept_valid_symbol_name(self, ida_client: rpyc.Connection) -> None:
        # Call capability using a valid function name
        result = ida_client.root.get_functions_called_recursively(address="main")
        assert result.success is True
        assert result.result["count"] >= 1

        root = result.result["root"]
        assert root["function_name"] == "main"

        # Verify returned function address resolves correctly
        resolved = ida_client.root.get_function_by_address(address=root["address"])
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

        # Ensure the starting function is the tree root
        assert result.result["root"]["function_name"] == "main"

    def test_returns_valid_function_entries(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="main")
        assert result.success is True

        root = result.result["root"]
        assert count_nodes(root) == result.result["count"]

        def check(node: dict) -> None:
            assert "function_name" in node
            assert "address" in node
            assert "children" in node
            assert node["function_name"] is not None
            # Every node's address should correspond to a valid function
            resolved = ida_client.root.get_function_by_address(address=node["address"])
            assert resolved.success is True
            assert resolved.result["name"] == node["function_name"]
            for child in node["children"]:
                check(child)

        check(root)

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

    def test_self_call(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="self_call")
        assert result.success is True
        assert result.result["count"] == 1

        root = result.result["root"]
        assert root["function_name"] == "self_call"
        # The recursive self-call is filtered out (already "seen"),
        # so the root should have no children
        assert len(root["children"]) == 0

    def test_parent(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.get_functions_called_recursively(address="max_depth_call")
        assert result.success is True

        # Walk down the tree; each node's parent-child relationship is now
        # expressed by nesting rather than an address-based "parent" field
        node = result.result["root"]
        depth = 1
        while node["children"]:
            assert len(node["children"]) == 1, (
                f"Expected a single chain at depth {depth}, got {len(node['children'])} children"
            )
            node = node["children"][0]
            depth += 1

        assert depth == 6
