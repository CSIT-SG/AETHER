from __future__ import annotations

from dataclasses import dataclass

from openai import APIConnectionError, APIStatusError, APITimeoutError, AsyncOpenAI


@dataclass(frozen=True)
class GatewaySupport:
    supported: bool
    detail: str
    # HTTP status of the probe, or None when no response was received at all
    # (offline, gateway unreachable, or a timeout). Use `status_code is None` to
    # distinguish "couldn't connect" from a gateway that answered with an error.
    status_code: int | None = None


async def probe_gateway(client: AsyncOpenAI, model: str) -> GatewaySupport:
    """Verifies the gateway accepts the API key and handles OpenAI-compatible requests.

    Sends a minimal chat.completions request to the configured endpoint. To remain
    provider-agnostic (e.g., OpenRouter, llama.cpp), it avoids probing provider-specific
    features or assuming uniform tool support. On failure it reports the gateway's own
    error message. Reads real HTTP status and on occasion other than 200 will print message
    """
    try:
        response = await client.chat.completions.with_raw_response.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
    except APIStatusError as e:  # any 4xx/5xx, incl. 401 — surface the provider's reason
        return GatewaySupport(False, _error_message(e), e.status_code)
    except APITimeoutError:  # request sent but no reply in time (must precede the parent)
        return GatewaySupport(False, "The gateway did not respond in time (timeout).", None)
    except APIConnectionError:  # no response at all: offline, DNS failure, refused, bad URL
        return GatewaySupport(
            False,
            "Could not reach the gateway — check your internet connection or the gateway URL.",
            None,
        )

    status = response.status_code
    if status == 200:
        return GatewaySupport(True, f"The gateway accepted the request (HTTP {status}).", status)
    return GatewaySupport(False, f"Unexpected non-success status (HTTP {status}).", status)


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
        if body.get("message"):  # inner error object, as the SDK usually exposes it
            return str(body["message"])
        err = body.get("error")  # full envelope
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str) and err:
            return err
    return error.message or f"HTTP {error.status_code}"
