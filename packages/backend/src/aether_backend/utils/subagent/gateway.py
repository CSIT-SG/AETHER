from aether_utils.api_client import create_async_httpx_client, create_async_openai_client
from aether_utils.config import get_config
from agents import (
    Model,
    OpenAIChatCompletionsModel,
    set_tracing_disabled,
)


class OpenAIGateway:
    """A gateway for interacting with OpenAI's API, handling client configuration and connection management.

    example usage:
    ```python
    gateway = OpenAIGateway()
    model = gateway.get_model(model_name="gpt-4", feature="my_feature")
    agent = Agent(model=model)
    ```
    """

    def __init__(self) -> None:
        self.config = get_config()

        set_tracing_disabled(True)

    def get_model(
        self,
        *,
        model_name: str | None = None,
        feature: str | None = None,
    ) -> Model:
        """Create a Model with an OpenAI client configured according to the gateway's settings."""
        if self.config.tls and self.config.tls.client_cert_path and self.config.tls.client_key_path:
            httpx_client = create_async_httpx_client(
                client_cert_path=self.config.tls.client_cert_path,
                client_key_path=self.config.tls.client_key_path,
            )
        else:
            httpx_client = create_async_httpx_client()

        if not self.config.provider.api_key:
            raise ValueError("OpenAI API key is not set in the configuration.")

        client = create_async_openai_client(
            api_key=self.config.provider.api_key,
            base_url=self.config.provider.gateway_url,
            httpx_client=httpx_client,
            feature=feature,
        )

        if model_name is not None:
            resolved_model_name = self.config.provider.models[model_name]
        else:
            resolved_model_name = self.config.provider.models[self.config.provider.default_model]

        return OpenAIChatCompletionsModel(model=resolved_model_name, openai_client=client)
