from __future__ import annotations

from openai import APIConnectionError, APIStatusError, APITimeoutError, AsyncOpenAI

from .contract import CheckResult


async def probe_gateway(client: AsyncOpenAI, model: str) -> CheckResult:
    """Verifies the gateway accepts the API key and handles OpenAI-compatible requests.

    Sends a minimal chat.completions request to the configured endpoint. To remain
    provider-agnostic (e.g., OpenRouter, llama.cpp), it avoids probing provider-specific
    features or assuming uniform tool support. On failure it reports the gateway's own
    error message. The real HTTP status is read from the raw response, so only a 200 is
    treated as success; any other status is returned with its code.
    """
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
    """The provider's own error text, with fallbacks.

    OpenAI-compatible gateways report the reason as a JSON error object; surface that
    text directly rather than guessing from the status code. The SDK usually exposes it
    already unwrapped on ``error.body`` (``{"message": ..., "code": ...}``), but some
    return the full ``{"error": {"message": ...}}`` envelope, so handle both. A proxy or
    minimal gateway may return non-JSON (an HTML 502, an empty 403), so fall back to the
    SDK's message and the bare status code.
    """
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
