from .models import ConfigModel, ProviderModel

DEFAULT_MODEL_LIST = {
    "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
    "OpenAI: gpt-oss-120b": "openai/gpt-oss-120b",
    "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct",
}

DEFAULT_OPENROUTER_GATEWAY_URL = "https://openrouter.ai/api/v1"


DEFAULT_CONFIG = ConfigModel(
    provider=ProviderModel(
        gateway_url=DEFAULT_OPENROUTER_GATEWAY_URL,
        api_key="",
        models=DEFAULT_MODEL_LIST,
        default_model="OpenAI: gpt-oss-120b",
    ),
)
