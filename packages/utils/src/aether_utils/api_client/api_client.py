from os import path

import httpx
from openai import AsyncOpenAI

from aether_utils.find_root import get_version
from aether_utils.logger import get_logger

VERSION = get_version()
logger = get_logger("aether_utils.api_client")


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


def _build_user_agent_header(feature: str | None) -> dict[str, str]:
    user_agent = f"AETHER (IDA)/{VERSION}-{feature}" if feature else f"AETHER (IDA)/{VERSION}"

    logger.info(f"Added User-Agent header: {user_agent}")
    return {"User-Agent": user_agent}


def create_async_httpx_client(
    *,
    client_cert_path: str = "",
    client_key_path: str = "",
) -> httpx.AsyncClient:
    """Create an Async HTTPX client with optional mTLS configuration.

    This function builds a low-level transport (`httpx.AsyncClient`) that
    handles optional mTLS certificate/key configuration. Keeping transport
    creation separate from the OpenAI client allows reusing the same HTTP
    transport (and its connection pool / certificate configuration) across
    multiple higher-level clients or requests.

    Example:

        httpx_client = create_async_httpx_client(
            client_cert_path="path/to/cert.pem",
            client_key_path="path/to/key.pem",
        )
        openai_client = create_async_openai_client(
            api_key="sk-...",
            base_url="https://api.example.com",
            httpx_client=httpx_client,
            feature="chat",
        )
        # use openai_client...
        await httpx_client.aclose()
    """
    client_cert_key = _build_client_cert_key(client_cert_path, client_key_path)
    return _create_httpx_client(client_cert_key)


def create_async_openai_client(
    *,
    api_key: str,
    base_url: str,
    httpx_client: httpx.AsyncClient,
    feature: str | None = None,
) -> AsyncOpenAI:
    """Create an `AsyncOpenAI` client using an existing `httpx.AsyncClient`.

    The OpenAI client is a thin wrapper that requires an HTTP transport. By
    separating transport (`httpx.AsyncClient`) creation from the higher-level
    OpenAI client we let callers reuse a single, configured transport for
    connection pooling, shared timeouts, mTLS, proxies, etc.

    Example:

        httpx_client = create_async_httpx_client()
        openai_client = create_async_openai_client(
            api_key="sk-...",
            base_url="https://api.example.com",
            httpx_client=httpx_client,
            feature="indexing",
        )

    """
    custom_headers = _build_user_agent_header(feature)

    if not api_key:
        logger.warning("API key not provided! Set one in the AETHER config.")

    if not base_url:
        logger.warning("Base URL not provided! Set one in the AETHER config.")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        http_client=httpx_client,
        default_headers=custom_headers,
    )
    return client
