from __future__ import annotations

from dataclasses import dataclass

from openai import APIConnectionError, APIStatusError, AsyncOpenAI


@dataclass(frozen=True)
class AgentSupport:
    supported: bool
    detail: str  # the provider's own error text, or a success note
    status_code: int | None = None

    @property
    def invalid_key(self) -> bool:
        """The gateway explicitly rejected the API key (401)."""
        return self.status_code == 401


async def probe_gateway(client: AsyncOpenAI, model: str) -> AgentSupport:
    """Verifies the gateway accepts the API key and handles OpenAI-compatible requests.

    Sends a minimal chat.completions request to the configured endpoint. To remain
    provider-agnostic (e.g., OpenRouter, llama.cpp), it avoids probing provider-specific
    features or assuming uniform tool support. On failure it reports the gateway's own
    error message (except for 401, kept generic to avoid echoing a masked key).
    """
    try:
        await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
    except APIStatusError as e:
        # A 401's message can echo a masked key fragment (and detail is logged), so
        # keep that one generic; for every other status show the provider's own reason.
        detail = "The API key was rejected (401)." if e.status_code == 401 else _error_message(e)
        return AgentSupport(False, detail, e.status_code)
    except APIConnectionError:  # includes timeouts (APITimeoutError subclass)
        return AgentSupport(False, "Could not reach the gateway (network error).")

    return AgentSupport(True, "The gateway accepted the request and the API key is valid.", 200)


def _error_message(error: APIStatusError) -> str:
    """The provider's own error text, with fallbacks.

    OpenAI-compatible gateways return a ``{"error": {"message": ...}}`` body; surface
    that reason directly rather than guessing from the status code. A proxy or minimal
    gateway may return non-JSON (an HTML 502, an empty 403), so fall back to the SDK's
    message and finally the bare status code.
    """
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str) and err:
            return err
    return error.message or f"HTTP {error.status_code}"
