from __future__ import annotations

import httpx
from openai import AsyncOpenAI

from aether_utils.config import get_config
from aether_utils.logger import get_logger

from .get_support import AgentSupport, check_agent_support, check_openrouter_key

logger = get_logger("aether_utils.get_support")

# Keep the support probe shorter than normal agent requests.
_PROBE_TIMEOUT_S = 15.0

_OPENROUTER_HOST = "openrouter.ai"


async def verify_agent_support() -> AgentSupport:
    """Validate that the currently configured provider/model can run agents."""
    config = get_config()
    provider = config.provider
    model_id = provider.models.get(provider.default_model, provider.default_model)
    base_url = provider.gateway_url
    api_key = provider.api_key or ""

    tls = config.tls
    cert: tuple[str, str] | None = None
    if tls and tls.client_cert_path and tls.client_key_path:
        cert = (tls.client_cert_path, tls.client_key_path)

    httpx_client = httpx.AsyncClient(cert=cert, verify=True, timeout=_PROBE_TIMEOUT_S)
    try:
        client = AsyncOpenAI(api_key=api_key, base_url=base_url, http_client=httpx_client)
        result: AgentSupport | None = None
        if _OPENROUTER_HOST in base_url:
            result = await check_openrouter_key(httpx_client, base_url, api_key)
        if result is None or result.supported:  # non-OpenRouter, or key already known good
            result = await check_agent_support(client, model_id)
    finally:
        await httpx_client.aclose()

    if result.supported:
        logger.info("Agent support confirmed for '%s': %s", model_id, result.detail)
    else:
        logger.warning(
            "Agent support check failed for '%s' (%s): %s",
            model_id,
            result.status_code,
            result.detail,
        )
    return result
