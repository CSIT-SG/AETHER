# Keys for the grouped subagents config
SUBAGENT_KEYS = (
    "gatherer_model",
    "annotator_model",
    "ai_decomp_model",
    "single_analysis_model",
    "struct_creator_model",
    "index_agent_model",
)

DEFAULT_MODEL_LIST = {
    "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
    "OpenAI: gpt-oss-120b": "openai/gpt-oss-120b",
    "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct",
}
