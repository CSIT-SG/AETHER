from .models import ConfigModel, ProviderModel, SubagentsModel

DEFAULT_MODEL_LIST = {
    "GLM 5.3": "z-ai/glm-5.3-flash",
    "Qwen3.5 Coder": "qwen/qwen3.5-397b-a17b",
    "Qwen3-next Instruct": "qwen/qwen3-next-80b-a3b-instruct",
    "Minimax m2.7": "minimax/minimax-m2.7",
    "Gemini 3.7": "google/gemini-3.7-flash",
    "Minimax m3": "minimax/minimax-m3",
}

DEFAULT_OPENROUTER_GATEWAY_URL = "https://openrouter.ai/api/v1"


DEFAULT_CONFIG = ConfigModel(
    provider=ProviderModel(
        gateway_url=DEFAULT_OPENROUTER_GATEWAY_URL,
        api_key="",
        models=DEFAULT_MODEL_LIST,
        default_model="Minimax m2.7",
    ),
    subagents=SubagentsModel(
        annotator_model="Qwen3-next Instruct",
        struct_reevaluator_model="GLM 5.3",
        struct_creator_model="Gemini 3.7",
    ),
)
