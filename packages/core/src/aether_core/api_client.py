from os import path

import httpx
from aether_utils.find_root import get_version
from aether_utils.logger import get_logger
from openai import AsyncOpenAI

VERSION = get_version()
logger = get_logger("aether_core.api_client")


def _build_client_cert_key(client_cert_path: str, client_key_path: str) -> tuple[str, str] | None:

    if not client_cert_path and not client_key_path:
        logger.warning(
            "CLIENT_CERT_PATH and CLIENT_KEY_PATH not provided. Proceeding without client certificate."
        )
        return None

    if not path.exists(client_cert_path):
        logger.warning(
            f"Client certificate file not found: {client_cert_path}. Proceeding without client certificate."
        )
        return None

    if not path.exists(client_key_path):
        logger.warning(
            f"Client key file not found: {client_key_path}. Proceeding without client certificate."
        )
        return None

    logger.info(f"Using client certificate: {client_cert_path} with key: {client_key_path}")
    return (client_cert_path, client_key_path)


def _create_httpx_client(client_cert_key: tuple[str, str] | None) -> httpx.AsyncClient:
    TIMEOUT = 600  # 10 minutes
    if not client_cert_key:
        logger.info(
            "No client certificate provided. Creating Async HTTPX client without client cert."
        )
        return httpx.AsyncClient(verify=False, timeout=TIMEOUT)

    return httpx.AsyncClient(cert=client_cert_key, verify=False, timeout=TIMEOUT)


def _build_user_agent_header(feature: str) -> dict[str, str]:
    if feature:
        user_agent = f"AETHER (IDA)/alpha{VERSION}-{feature}"
    else:
        user_agent = f"AETHER (IDA)/alpha{VERSION}"

    logger.info(f"Added User-Agent header: {user_agent}")
    return {"User-Agent": user_agent}


def create_async_httpx_client(
    *,
    client_cert_path: str = "",
    client_key_path: str = "",
) -> httpx.AsyncClient:
    """Create an Async HTTPX client with optional mTLS configuration."""
    client_cert_key = _build_client_cert_key(client_cert_path, client_key_path)
    return _create_httpx_client(client_cert_key)


def create_async_openai_client(
    *,
    api_key: str,
    base_url: str,
    httpx_client: httpx.AsyncClient,
    feature: str = "",
) -> AsyncOpenAI:

    custom_headers = _build_user_agent_header(feature)

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        http_client=httpx_client,
        default_headers=custom_headers,
    )
    return client
