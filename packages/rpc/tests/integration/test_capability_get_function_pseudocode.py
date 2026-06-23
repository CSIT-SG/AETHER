# type: ignore
import pytest
import rpyc


@pytest.mark.dependency(depends=["connection"], scope="session")
class TestGetFunctionPseudocode:
    """Tests for Getting Function Pseudocode"""

    def test_get_valid_func_pseuodocode(self, ida_client: rpyc.Connection) -> None:
        # Assert valid decompiled pseudocode
        data = ida_client.root.get_function_pseudocode(function_name="main")
        assert data.success is True
        pseudo = data.result["pseudocode"]

        assert pseudo is not None
        assert "return 0" in pseudo

    def test_get_invalid_func_pseudocode(self, ida_client: rpyc.Connection) -> None:
        # Assert invalid function decompilation
        data = ida_client.root.get_function_pseudocode(function_name="balls")

        assert data.success is False
