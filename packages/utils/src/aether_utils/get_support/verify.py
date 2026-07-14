from __future__ import annotations

from aether_utils.api_client import create_async_httpx_client, create_async_openai_client
from aether_utils.config import get_config
from aether_utils.logger import get_logger

from .get_support import AgentSupport, probe_gateway

logger = get_logger("aether_utils.get_support")


async def verify_provider() -> AgentSupport:
    """Validate the currently-configured OpenAI-compatible provider/model and key."""
    config = get_config()
    provider = config.provider
    model_id = provider.models.get(provider.default_model, provider.default_model)
    base_url = provider.gateway_url
    api_key = provider.api_key or ""

    tls = config.tls
    httpx_client = create_async_httpx_client(
        client_cert_path=(tls.client_cert_path or "") if tls else "",
        client_key_path=(tls.client_key_path or "") if tls else "",
    )
    try:
        client = create_async_openai_client(
            api_key=api_key, base_url=base_url, httpx_client=httpx_client, feature="config-check"
        )
        result = await probe_gateway(client, model_id)
    finally:
        await httpx_client.aclose()

    if result.supported:
        logger.info("Provider check OK for '%s': %s", model_id, result.detail)
    else:
        logger.warning(
            "Provider check failed for '%s' (%s): %s", model_id, result.status_code, result.detail
        )
    return result
