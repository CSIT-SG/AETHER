from __future__ import annotations

from openai import APIConnectionError, APIStatusError, APITimeoutError, AsyncOpenAI

from .contract import CheckResult


async def probe_gateway(client: AsyncOpenAI, model: str) -> CheckResult:
    """Verifies the gateway accepts the API key and handles OpenAI-compatible requests."""
    try:
        response = await client.chat.completions.with_raw_response.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
    except APIStatusError as e:  # any 4xx/5xx
        return CheckResult(False, f"{_error_message(e)} (HTTP {e.status_code})", e.status_code)
    except APITimeoutError:  # request sent but no reply
        return CheckResult(False, "The gateway did not respond in time (timeout).", None)
    except APIConnectionError:  # no response
        return CheckResult(
            False,
            "Could not reach the gateway — check your internet connection or the gateway URL.",
            None,
        )

    status = response.status_code
    if status == 200:
        return CheckResult(True, f"The gateway accepted the request (HTTP {status}).", status)
    return CheckResult(False, f"Unexpected non-success status (HTTP {status}).", status)


def _error_message(error: APIStatusError) -> str:
    """The provider's own error text, with fallbacks."""
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        if body.get("message"):
            return str(body["message"])
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str) and err:
            return err
    return error.message or "The gateway returned an error"
