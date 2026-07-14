from typing import Any, cast

import httpx
import pytest
from aether_utils.get_support import probe_gateway
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
    result = await probe_gateway(_client(), "some-model")
    assert result.supported is True
    assert result.status_code == 200
    assert result.invalid_key is False


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (_status_error(AuthenticationError, 401), 401),
        (_status_error(PermissionDeniedError, 403), 403),
        (_status_error(NotFoundError, 404), 404),
        (_status_error(BadRequestError, 400), 400),
        (_status_error(RateLimitError, 429), 429),
        (_status_error(APIStatusError, 500), 500),
    ],
)
async def test_status_errors(exc: Exception, code: int) -> None:
    result = await probe_gateway(_client(exc), "m")
    assert result.supported is False
    assert result.status_code == code
    assert result.detail  # non-empty text, taken from the provider's own error


async def test_invalid_key_only_on_401() -> None:
    rejected = await probe_gateway(_client(_status_error(AuthenticationError, 401)), "m")
    not_found = await probe_gateway(_client(_status_error(NotFoundError, 404)), "m")
    assert rejected.invalid_key is True
    assert not_found.invalid_key is False


async def test_network_error() -> None:
    request = httpx.Request("POST", "https://gateway.test")
    result = await probe_gateway(_client(APIConnectionError(request=request)), "m")
    assert result.supported is False
    assert result.status_code is None
