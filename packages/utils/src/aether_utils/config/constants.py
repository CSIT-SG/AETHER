from .models import ConfigModel, ProviderModel, ProviderType

DEFAULT_MODEL_LIST = {
    "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
    "OpenAI: gpt-oss-120b": "openai/gpt-oss-120b",
    "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct",
}


DEFAULT_CONFIG = ConfigModel(
    provider=ProviderModel(
        type=ProviderType.OPENROUTER,
        api_key="",
        models=DEFAULT_MODEL_LIST,
        default_model="OpenAI: gpt-oss-120b",
    ),
)
