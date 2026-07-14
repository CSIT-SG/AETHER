from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    import httpx
    from openai import AsyncOpenAI

# Exercise tool calling so chat-only models do not pass the agent support probe.
_PROBE_TOOL: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "aether_support_probe",
            "description": "No-op used to confirm the model supports tool calling.",
            "parameters": {"type": "object", "properties": {}},
        },
    }
]


@dataclass(frozen=True)
class AgentSupport:
    supported: bool
    detail: str  # the provider's own error text, or a success note
    status_code: int | None = None
    # Transient failures (network, rate limit, 5xx, out-of-credit) must not be cached.
    cacheable: bool = True


async def check_agent_support(client: AsyncOpenAI, model: str) -> AgentSupport:
    """Confirm a provider/model can run agents with a single-token tool probe."""
    # Lazy import so merely importing this module (e.g. for the cache helpers) skips openai.
    from openai import APIConnectionError, APIStatusError, RateLimitError

    try:
        await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
            tools=cast("Any", _PROBE_TOOL),
            tool_choice="auto",
        )
    except RateLimitError as e:  # key works, just rate-limited — inconclusive
        msg = "Rate limited (429); the key works but the check couldn't complete."
        return AgentSupport(False, msg, e.status_code, cacheable=False)
    except APIStatusError as e:
        if e.status_code == 401:
            return AgentSupport(False, "The API key was rejected (401).", 401)
        if e.status_code == 402:  # valid key, no credit — distinct from a bad key, transient
            return AgentSupport(
                False, "API key has no remaining credit (402).", 402, cacheable=False
            )
        # 400/403/404 are stable; 5xx are server-side and transient.
        detail = f"{_provider_message(e)} (HTTP {e.status_code})."
        return AgentSupport(False, detail, e.status_code, cacheable=e.status_code < 500)
    except APIConnectionError:  # includes timeouts (APITimeoutError subclass)
        return AgentSupport(False, "Could not reach the gateway (network error).", cacheable=False)

    return AgentSupport(True, "Model responded and supports tool calling.", 200)


def _provider_message(error: Any) -> str:
    """Return the cleanest provider message from an APIStatusError."""
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str) and err:
            return err
    message = getattr(error, "message", None)
    return str(message) if message else str(error)


async def check_openrouter_key(
    http_client: httpx.AsyncClient, base_url: str, api_key: str
) -> AgentSupport:
    """Validate an OpenRouter key via ``GET /auth/key`` without spending tokens."""
    import httpx

    url = f"{base_url.rstrip('/')}/auth/key"
    try:
        resp = await http_client.get(url, headers={"Authorization": f"Bearer {api_key}"})
    except httpx.RequestError:
        return AgentSupport(False, "Could not reach OpenRouter (network error).", cacheable=False)

    if resp.status_code == 401:
        return AgentSupport(False, "OpenRouter rejected the API key (401).", 401)
    if resp.status_code != 200:
        return AgentSupport(
            False,
            f"OpenRouter key check failed ({resp.status_code}).",
            resp.status_code,
            cacheable=resp.status_code < 500,
        )

    try:
        data = resp.json().get("data", {})
    except ValueError:
        data = {}
    limit = data.get("limit")
    usage = data.get("usage")
    remaining = data.get("limit_remaining")
    if remaining is None and limit is not None and usage is not None:
        remaining = limit - usage
    if remaining is not None and remaining <= 0:
        return AgentSupport(
            False, "OpenRouter key is valid but has no remaining credit.", 402, cacheable=False
        )

    return AgentSupport(True, "OpenRouter key is valid.", 200)
