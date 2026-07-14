from typing import Any, cast

import httpx
import pytest
from aether_utils.get_support import probe_gateway
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
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


class _RawResponse:
    def __init__(self, status: int) -> None:
        self.status_code = status


class _FakeWithRawResponse:
    def __init__(self, exc: Exception | None, status: int) -> None:
        self._exc = exc
        self._status = status

    async def create(self, **_: Any) -> _RawResponse:
        if self._exc is not None:
            raise self._exc
        return _RawResponse(self._status)


class _FakeCompletions:
    def __init__(self, exc: Exception | None, status: int) -> None:
        # probe_gateway calls chat.completions.with_raw_response.create(...)
        self.with_raw_response = _FakeWithRawResponse(exc, status)


class _FakeClient:
    """Minimal stand-in for AsyncOpenAI exposing chat.completions.with_raw_response."""

    def __init__(self, exc: Exception | None = None, status: int = 200) -> None:
        self.chat = type("Chat", (), {"completions": _FakeCompletions(exc, status)})()


def _client(exc: Exception | None = None, status: int = 200) -> AsyncOpenAI:
    return cast(AsyncOpenAI, _FakeClient(exc, status))


@pytest.mark.parametrize(
    ("status", "supported"),
    # Only an exact 200 counts as valid; 201/302 must not be reported as valid.
    [(200, True), (201, False), (302, False)],
)
async def test_success_status(status: int, supported: bool) -> None:
    result = await probe_gateway(_client(status=status), "m")
    assert result.supported is supported
    assert result.status_code == status


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
    result = await probe_gateway(_client(exc=exc), "m")
    assert result.supported is False
    assert result.status_code == code
    assert result.detail  # non-empty, taken from the provider's own error


@pytest.mark.parametrize(
    "body",
    [
        {"message": "bad key", "code": 401},  # inner error object (usual SDK shape)
        {"error": {"message": "bad key"}},  # full envelope
    ],
)
async def test_error_message_extracted(body: dict[str, Any]) -> None:
    err = AuthenticationError("Error code: 401 - ...", response=_response(401), body=body)
    result = await probe_gateway(_client(exc=err), "m")
    assert result.detail == "bad key"  # provider's own reason, not the SDK wrapper


async def test_no_response_has_no_status() -> None:
    # No internet / unreachable gateway / timeout: no HTTP response, so status is None.
    request = httpx.Request("POST", "https://gateway.test")
    for exc in (APIConnectionError(request=request), APITimeoutError(request=request)):
        result = await probe_gateway(_client(exc=exc), "m")
        assert result.supported is False
        assert result.status_code is None
