from aether_utils.api_client import create_async_httpx_client, create_async_openai_client
from aether_utils.config import get_config
from openai import AsyncOpenAI
from agents import (
    Model,
    ModelProvider,
    OpenAIChatCompletionsModel,
    RunConfig,
    set_tracing_disabled,
)
from typing import cast


class OpenAIGateway:
    """A gateway for interacting with OpenAI's API, handling client configuration and connection management.

    example usage:
    ```python
    gateway = OpenAIGateway(feature="my_feature")
    run_config = gateway.create_run_config()
    agent = Agent(..., run_config=run_config)  # create your agent with tools, etc.
        ```
    """

    def __init__(self, *, feature: str) -> None:
        self.config = get_config()
        self.feature = feature

    def create_run_config(
        self,
        model_name: str | None = None,
    ) -> RunConfig:
        """Create a RunConfig with an OpenAI client configured according to the gateway's settings."""
        if self.config.tls:
            httpx_client = create_async_httpx_client(
                client_cert_path=self.config.tls.client_cert_path,
                client_key_path=self.config.tls.client_key_path,
            )
        else:
            httpx_client = create_async_httpx_client()

        client = cast(
            AsyncOpenAI,
            create_async_openai_client(
                api_key=self.config.provider.api_key,
                base_url=self.config.provider.gateway_url,
                httpx_client=httpx_client,
                feature=self.feature,
            ),
        )
        set_tracing_disabled(True)

        resolved_model_name = model_name or self.config.provider.default_model

        class _ModelProvider(ModelProvider):
            def get_model(self, model_name: str | None) -> Model: # we ignore the model_name as it is controlled by the gateway's config
                return OpenAIChatCompletionsModel(model=resolved_model_name, openai_client=client)

        return RunConfig(model_provider=_ModelProvider())
