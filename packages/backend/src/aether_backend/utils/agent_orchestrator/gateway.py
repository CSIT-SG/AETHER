from aether_utils.api_client import create_async_httpx_client, create_async_openai_client
from aether_utils.config import get_config
from httpx import AsyncClient
from openai import AsyncOpenAI
from typing import cast


class OpenAIGateway:
    """A gateway for interacting with OpenAI's API, handling client configuration and connection management.
    
    example usage:
    ```python
    gateway = OpenAIGateway(feature="my_feature")
    response = await gateway.client.chat.completions.create(model="gpt-4o", messages=[...])
    ...
    await gateway.stop()  # immdiately close the connection and recreate the client for the next operation
    ```

    streaming:
    ```python
    gateway = OpenAIGateway(feature="my_feature")

    try:
        async with gateway.client.chat.completions.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello!"}],
        ) as stream:
            async for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    print(delta, end="", flush=True)
    finally:
        await gateway.stop(recreate=False)  # close the connection without recreating the client, since we won't be making any more requests
    ```
    """
    def __init__(self, *, feature: str) -> None:
        self.config = get_config()
        self.feature = feature

        self.httpx_client = self._create_httpx_client()
        self.client = self._create_client()

    def _create_httpx_client(self) -> AsyncClient:
        if self.config.tls:
            httpx_client = create_async_httpx_client(
                client_cert_path=self.config.tls.client_cert_path,
                client_key_path=self.config.tls.client_key_path,
            )
        else:
            httpx_client = create_async_httpx_client()
        return cast(AsyncClient, httpx_client)

    def _create_client(
        self,
    ) -> AsyncOpenAI:
        return cast(
            AsyncOpenAI,
            create_async_openai_client(
                api_key=self.config.provider.api_key,
                base_url=self.config.provider.gateway_url,
                httpx_client=self.httpx_client,
                feature=self.feature,
            ),
        )

    async def stop(self, recreate: bool = True) -> None:
        """Close the http connection. Ok to call when user cancels the operation."""
        await self.httpx_client.aclose()

        # recreate the client with a new httpx client for the next operation, since httpx clients cannot be reopened once closed.
        if recreate:
            self.httpx_client = self._create_httpx_client()
            self.client = self._create_client()
