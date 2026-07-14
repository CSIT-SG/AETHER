from typing import Any, cast

import httpx
import pytest
from aether_utils.get_support import (
    check_agent_support,
    check_openrouter_key,
)
from openai import (
    APIConnectionError,
    APIStatusError,
    AsyncOpenAI,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)


def _response(status: int) -> httpx.Response:
    request = httpx.Request("POST", "https://gateway.test/v1/chat/completions")
    return httpx.Response(status, request=request)


def _status_error(cls: type[APIStatusError], status: int) -> APIStatusError:
    return cls("provider message", response=_response(status), body=None)


class _FakeCompletions:
    def __init__(self, exc: Exception | None) -> None:
        self._exc = exc

    async def create(self, **_: Any) -> str:
        if self._exc is not None:
            raise self._exc
        return "ok"


class _FakeClient:
    """Minimal stand-in for AsyncOpenAI exposing chat.completions.create."""

    def __init__(self, exc: Exception | None = None) -> None:
        self.chat = type("Chat", (), {"completions": _FakeCompletions(exc)})()


def _client(exc: Exception | None = None) -> AsyncOpenAI:
    return cast(AsyncOpenAI, _FakeClient(exc))


async def test_supported() -> None:
    result = await check_agent_support(_client(), "some-model")
    assert result.supported is True
    assert result.status_code == 200
    assert result.cacheable is True


@pytest.mark.parametrize(
    ("exc", "code", "cacheable"),
    [
        (_status_error(AuthenticationError, 401), 401, True),
        (_status_error(PermissionDeniedError, 403), 403, True),
        (_status_error(NotFoundError, 404), 404, True),
        (_status_error(BadRequestError, 400), 400, True),
        (_status_error(RateLimitError, 429), 429, False),  # transient
        (_status_error(APIStatusError, 500), 500, False),  # server error, transient
    ],
)
async def test_status_errors(exc: Exception, code: int, cacheable: bool) -> None:
    result = await check_agent_support(_client(exc), "m")
    assert result.supported is False
    assert result.status_code == code
    assert result.cacheable is cacheable
    assert result.detail  # non-empty text, taken from the provider's own error


async def test_network_error() -> None:
    request = httpx.Request("POST", "https://gateway.test")
    result = await check_agent_support(_client(APIConnectionError(request=request)), "m")
    assert result.supported is False
    assert result.status_code is None
    assert result.cacheable is False


async def test_no_credit() -> None:
    result = await check_agent_support(_client(_status_error(APIStatusError, 402)), "m")
    assert result.supported is False
    assert result.status_code == 402
    assert result.cacheable is False  # topping up credit fixes it
    assert "credit" in result.detail.lower()


# --- OpenRouter GET /auth/key ---------------------------------------------------------

_OPENROUTER_BASE = "https://openrouter.ai/api/v1"


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _FakeHttpClient:
    def __init__(self, response: _FakeResponse | None = None, exc: Exception | None = None) -> None:
        self._response = response
        self._exc = exc
        self.requested_url: str | None = None

    async def get(self, url: str, headers: dict[str, str] | None = None) -> _FakeResponse:
        self.requested_url = url
        if self._exc is not None:
            raise self._exc
        assert self._response is not None
        return self._response


def _http_client(client: _FakeHttpClient) -> httpx.AsyncClient:
    return cast(httpx.AsyncClient, client)


async def test_openrouter_valid_key() -> None:
    client = _FakeHttpClient(_FakeResponse(200, {"data": {"limit": 10, "usage": 3}}))
    result = await check_openrouter_key(_http_client(client), _OPENROUTER_BASE, "k")
    assert result.supported is True
    assert result.status_code == 200
    assert client.requested_url == f"{_OPENROUTER_BASE}/auth/key"


async def test_openrouter_no_credit() -> None:
    client = _FakeHttpClient(_FakeResponse(200, {"data": {"limit": 10, "usage": 10}}))
    result = await check_openrouter_key(_http_client(client), _OPENROUTER_BASE, "k")
    assert result.supported is False
    assert result.status_code == 402
    assert result.cacheable is False


async def test_openrouter_limit_remaining() -> None:
    client = _FakeHttpClient(_FakeResponse(200, {"data": {"limit_remaining": 0}}))
    result = await check_openrouter_key(_http_client(client), _OPENROUTER_BASE, "k")
    assert result.status_code == 402


async def test_openrouter_rejects_key() -> None:
    client = _FakeHttpClient(_FakeResponse(401))
    result = await check_openrouter_key(_http_client(client), _OPENROUTER_BASE, "k")
    assert result.supported is False
    assert result.status_code == 401


async def test_openrouter_server_error() -> None:
    client = _FakeHttpClient(_FakeResponse(503))
    result = await check_openrouter_key(_http_client(client), _OPENROUTER_BASE, "k")
    assert result.supported is False
    assert result.status_code == 503
    assert result.cacheable is False


async def test_openrouter_network_error() -> None:
    request = httpx.Request("GET", f"{_OPENROUTER_BASE}/auth/key")
    client = _FakeHttpClient(exc=httpx.ConnectError("boom", request=request))
    result = await check_openrouter_key(_http_client(client), _OPENROUTER_BASE, "k")
    assert result.supported is False
    assert result.cacheable is False
