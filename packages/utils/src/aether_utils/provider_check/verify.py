from __future__ import annotations

from aether_utils.api_client import create_async_httpx_client, create_async_openai_client
from aether_utils.config import get_config
from aether_utils.logger import get_logger

from .contract import CheckResult
from .gateway import probe_gateway

logger = get_logger("aether_utils.provider_check")


async def verify_provider(api_key: str | None = None) -> CheckResult:
    """Validate the currently-configured OpenAI-compatible provider/model and key.

    If ``api_key`` is given, that key is checked instead of the saved one (the gateway
    URL, model and TLS still come from the saved config), so the settings UI can validate
    a key the user has typed but not yet saved.
    """
    config = get_config()
    provider = config.provider
    model_id = provider.models[provider.default_model]
    base_url = provider.gateway_url
    if api_key is None:
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

    if result.verdict:
        logger.info("Provider check OK for '%s': %s", model_id, result.detail)
    else:
        logger.warning(
            "Provider check failed for '%s' (%s): %s", model_id, result.status_code, result.detail
        )
    return result
