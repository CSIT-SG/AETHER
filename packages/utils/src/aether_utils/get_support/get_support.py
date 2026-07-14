from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from openai import AsyncOpenAI


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
    features or assuming uniform tool support.

    Exposes status_code for custom branching and forwards the provider's own error
    message via detail (except for 401s). Only openai client transport/HTTP errors
    are handled; all others propagate.
    """
    # Lazy import so importing this module (e.g. just for AgentSupport) skips openai.
    from openai import APIConnectionError, APIStatusError, RateLimitError

    try:
        await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
    except RateLimitError as e:  # key works, just rate-limited — inconclusive
        msg = "Rate limited (429); the key works but the check couldn't complete."
        return AgentSupport(False, msg, e.status_code)
    except APIStatusError as e:
        if e.status_code == 401:
            return AgentSupport(False, "The API key was rejected (401).", 401)
        return AgentSupport(False, f"{_error_message(e)} (HTTP {e.status_code}).", e.status_code)
    except APIConnectionError:  # includes timeouts (APITimeoutError subclass)
        return AgentSupport(False, "Could not reach the gateway (network error).")

    return AgentSupport(True, "The gateway accepted the request and the API key is valid.", 200)


def _error_message(error: Any) -> str:
    """Cleanest message from an APIStatusError: the provider's ``body.error.message`` if
    present, else the SDK's ``message``/``str`` (avoids the verbose ``Error code: NNN`` wrapper).
    """
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str) and err:
            return err
    message = getattr(error, "message", None)
    return str(message) if message else str(error)
