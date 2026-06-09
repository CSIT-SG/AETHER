# type: ignore
import rpyc
import pytest

@pytest.mark.dependency(name="connection", scope="session")
@pytest.mark.order(1)
class TestLiveCapabilities:
    def test_connection_is_alive(self, ida_client: rpyc.Connection) -> None:
        assert ida_client.root is not None
