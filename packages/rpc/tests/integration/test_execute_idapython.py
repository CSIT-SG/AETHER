# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="package")
@pytest.mark.order(after="test_connection.py::TestLiveCapabilities::test_connection_is_alive")
class TestExecuteIDAPython:
    """Tests for valid code execution, output capture, IDA API access, and error handling."""

    def test_stdout_is_captured(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.execute_idapython(code="print('hello')")
        assert result.success is True
        assert "hello" in result.result

    def test_empty_code_returns_empty_output(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.execute_idapython(code="")
        assert result.success is True
        assert result.result == ""

    def test_ida_api_accessible(self, ida_client: rpyc.Connection) -> None:
        # idaapi should be in scope without an explicit import
        result = ida_client.root.execute_idapython(code="import idaapi\nprint(dir(idaapi))")
        assert result.success is True
        assert result.result.strip() != ""

    def test_multiline_code_executes(self, ida_client: rpyc.Connection) -> None:
        code = "\n".join(
            [
                "total = 0",
                "for i in range(5):",
                "    total += i",
                "print(total)",
            ]
        )
        result = ida_client.root.execute_idapython(code=code)
        assert result.success is True
        assert result.result.strip() == "10"

    def test_syntax_error_returns_failure(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.execute_idapython(code="def (")
        assert result.success is False
        assert result.result != ""

    def test_runtime_exception_returns_failure(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.execute_idapython(code="raise ValueError('boom')")
        assert result.success is False
        assert "boom" in result.result

    def test_undefined_name_returns_failure(self, ida_client: rpyc.Connection) -> None:
        result = ida_client.root.execute_idapython(code="print(this_does_not_exist)")
        assert result.success is False
