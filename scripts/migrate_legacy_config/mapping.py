import copy
from typing import Any

from .schema import FieldMapping, MigrationContext

FLAT_LEGACY_SENTINEL_KEYS = {"OPENAI_MODEL", "OPENAI_BASE_URL", "MODEL_LIST"}


def identity(value: Any, _ctx: MigrationContext) -> Any:
    return value


def blank_to_none(value: Any, _ctx: MigrationContext) -> Any:
    if value == "":
        return None
    return value


def dict_or_empty(value: Any, _ctx: MigrationContext) -> dict[str, Any]:
    if isinstance(value, dict):
        return copy.deepcopy(value)
    return {}


def model_list(value: Any, ctx: MigrationContext) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    models = {str(name): str(model_id) for name, model_id in value.items()}
    ctx.models.update(models)
    return copy.deepcopy(ctx.models)


def model_name(value: Any, ctx: MigrationContext) -> Any:
    if not isinstance(value, str) or value == "":
        return None
    if value in ctx.models:
        return value
    for name, model_id in ctx.models.items():
        if model_id == value:
            return name
    ctx.models[value] = value
    return value


FIELD_MAPPINGS: tuple[FieldMapping, ...] = (
    FieldMapping("MODEL_LIST", ("provider", "models"), model_list),
    FieldMapping("OPENAI_BASE_URL", ("provider", "gateway_url"), identity),
    FieldMapping("OPENAI_API_KEY", ("provider", "api_key"), identity),
    FieldMapping("OPENAI_MODEL", ("provider", "default_model"), model_name),
    FieldMapping("OPENAI_EXTRA_BODY", ("provider", "extra_body"), dict_or_empty),
    FieldMapping("GATHERER_MODEL", ("subagents", "gatherer_model"), model_name),
    FieldMapping("ANNOTATOR_MODEL", ("subagents", "annotator_model"), model_name),
    FieldMapping("SINGLE_ANALYSIS_MODEL", ("subagents", "single_analysis_model"), model_name),
    FieldMapping("STRUCT_CREATOR_MODEL", ("subagents", "struct_creator_model"), model_name),
    FieldMapping("INDEX_AGENT_MODEL", ("subagents", "index_agent_model"), model_name),
    FieldMapping("DEBUG", ("debug",), identity),
    FieldMapping("CLIENT_CERT_PATH", ("tls", "client_cert_path"), blank_to_none),
    FieldMapping("CLIENT_KEY_PATH", ("tls", "client_key_path"), blank_to_none),
)

DROPPED_FIELD_NOTES: dict[str, str] = {
    "AI_DECOMP_MODEL": "No AETHER Next subagent slot exists yet.",
    "ALWAYS_PROMPT_MODEL": "No static AETHER Next setting exists yet.",
    "ANALYSIS_MAX_TOKENS": "No static AETHER Next setting exists yet.",
    "ANNOTATOR_MAX_TOKENS": "No static AETHER Next setting exists yet.",
    "CHATBOT_IDX_DIALOG": "No static AETHER Next setting exists yet.",
    "CHATBOT_MAX_TOKENS": "No static AETHER Next setting exists yet.",
    "COMMENT_EVERY_LINE": "No static AETHER Next setting exists yet.",
    "CUSTOM_CA_CERT_PATH": "AETHER Next TLS config does not expose a custom CA path yet.",
    "DEOBFUSCATOR_MAX_TOKENS": "No static AETHER Next setting exists yet.",
    "INDEXING_BATCH_SIZE": "No static AETHER Next setting exists yet.",
    "INDEXING_DEBUG_LOGS": "No static AETHER Next setting exists yet.",
    "INDEXING_DECOMP_CHUNK_SIZE": "No static AETHER Next setting exists yet.",
    "INDEXING_DECOMP_HEARTBEAT_INTERVAL_S": "No static AETHER Next setting exists yet.",
    "INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES": "No static AETHER Next setting exists yet.",
    "INDEXING_FAILED_RETRY_MAX": "No static AETHER Next setting exists yet.",
    "INDEXING_MAX_FUNC_SIZE_BYTES": "No static AETHER Next setting exists yet.",
    "INDEXING_MAX_TOKENS": "No static AETHER Next setting exists yet.",
    "INDEXING_MODEL": "No static AETHER Next setting exists yet.",
    "INDEXING_PSEUDOCODE_CACHE_ENABLED": "No static AETHER Next setting exists yet.",
    "INDEXING_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC": "No static AETHER Next setting exists yet.",
    "INDEXING_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS": "No static AETHER Next setting exists yet.",
    "INDEXING_SLOW_DECOMP_THRESHOLD_S": "No static AETHER Next setting exists yet.",
    "INDEXING_STUCK_FUNCTION_THRESHOLD_S": "No static AETHER Next setting exists yet.",
    "MAX_ITERATIONS": "No static AETHER Next setting exists yet.",
    "MCP_SERVER_URL": "No static AETHER Next setting exists yet.",
    "PROMPT_TOKEN_WARNING": "No static AETHER Next setting exists yet.",
    "RENAME_FILTER_ENABLED": "No static AETHER Next setting exists yet.",
    "RENAME_FUNCS": "No static AETHER Next setting exists yet.",
    "RENAME_VARS": "No static AETHER Next setting exists yet.",
    "SYSTEM_PROMPT_AT_BOTTOM": "No static AETHER Next setting exists yet.",
    "UNFLATTEN_ATTEMPTS": "No static AETHER Next setting exists yet.",
    "USE_COMMENTS": "No static AETHER Next setting exists yet.",
    "USE_DESC": "No static AETHER Next setting exists yet.",
}
