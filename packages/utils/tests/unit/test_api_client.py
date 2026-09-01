from pathlib import Path
from typing import Any

import pytest
from aether_utils.api_client import api_client


def test_build_client_cert_key_returns_none_when_paths_not_provided() -> None:
    result = api_client._build_client_cert_key("", "")
    assert result is None


def test_build_client_cert_key_returns_none_when_cert_or_key_missing(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert")

    result = api_client._build_client_cert_key(str(cert_path), str(key_path))
    assert result is None

    result = api_client._build_client_cert_key(str(cert_path), "")
    assert result is None


def test_build_client_cert_key_returns_tuple_for_existing_files(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert")
    key_path.write_text("key")

    result = api_client._build_client_cert_key(str(cert_path), str(key_path))
    assert result == (str(cert_path), str(key_path))


def test_create_httpx_client_without_cert_is_configured_without_cert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class DummyAsyncClient:
        def __init__(
            self,
            verify: bool,
            timeout: int,
            cert: tuple[str, str] | None = None,
        ) -> None:
            captured["verify"] = verify
            captured["timeout"] = timeout
            captured["cert"] = cert

    monkeypatch.setattr(api_client.httpx, "AsyncClient", DummyAsyncClient)

    client = api_client._create_httpx_client(None)

    assert isinstance(client, DummyAsyncClient)
    assert captured["verify"] is False
    assert captured["timeout"] == 600
    assert captured["cert"] is None


def test_create_httpx_client_with_cert_pair_is_configured_with_cert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert")
    key_path.write_text("key")

    captured: dict[str, Any] = {}

    class DummyAsyncClient:
        def __init__(
            self,
            verify: bool,
            timeout: int,
            cert: tuple[str, str] | None = None,
        ) -> None:
            captured["verify"] = verify
            captured["timeout"] = timeout
            captured["cert"] = cert

    monkeypatch.setattr(api_client.httpx, "AsyncClient", DummyAsyncClient)

    client = api_client._create_httpx_client((str(cert_path), str(key_path)))

    assert isinstance(client, DummyAsyncClient)
    assert captured["verify"] is False
    assert captured["timeout"] == 600
    assert captured["cert"] == (str(cert_path), str(key_path))


def test_create_async_httpx_client_calls_create_httpx_client_with_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create_httpx_client(
        client_cert_key: tuple[str, str] | None,
    ) -> str:
        captured["client_cert_key"] = client_cert_key
        return "async-client"

    monkeypatch.setattr(api_client, "_create_httpx_client", fake_create_httpx_client)

    client = api_client.create_async_httpx_client()

    assert client == "async-client"
    assert captured["client_cert_key"] is None


def test_create_async_httpx_client_calls_create_async_httpx_client_with_cert_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert")
    key_path.write_text("key")

    captured: dict[str, Any] = {}

    def fake_create_httpx_client(
        client_cert_key: tuple[str, str] | None,
    ) -> str:
        captured["client_cert_key"] = client_cert_key
        return "async-client"

    monkeypatch.setattr(api_client, "_create_httpx_client", fake_create_httpx_client)

    client = api_client.create_async_httpx_client(
        client_cert_path=str(cert_path),
        client_key_path=str(key_path),
    )

    assert client == "async-client"
    assert captured["client_cert_key"] == (str(cert_path), str(key_path))


def test_build_user_agent_header_includes_feature_when_provided() -> None:
    headers = api_client._build_user_agent_header("search")

    assert "search" in headers["User-Agent"]


def test_create_async_openai_client_passes_api_key_base_url_httpx_client_and_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DummyAsyncOpenAI:
        def __init__(
            self,
            api_key: str,
            base_url: str,
            http_client: object,
            default_headers: dict[str, str],
        ) -> None:
            self.api_key = api_key
            self.base_url = base_url
            self.http_client = http_client
            self.default_headers = default_headers

    monkeypatch.setattr(api_client, "AsyncOpenAI", DummyAsyncOpenAI)

    httpx_client: Any = object()
    client = api_client.create_async_openai_client(
        api_key="test-key",
        base_url="https://api.example.com",
        httpx_client=httpx_client,
        feature="test-feature",
    )

    assert isinstance(client, DummyAsyncOpenAI)
    assert client.api_key == "test-key"
    assert client.base_url == "https://api.example.com"
    assert client.http_client is httpx_client
    assert (
        client.default_headers["User-Agent"]
        == f"AETHER (IDA)/alpha{api_client.VERSION}-test-feature"
    )
