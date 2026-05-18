"""
AETHER config handling
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from aether_utils.find_root import find_repo_root
from aether_utils.logger import get_logger
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


def get_config_file_path() -> Path:
    repo_root: Path = find_repo_root()
    gui_src = repo_root / "apps" / "gui" / "src"
    gui_src.mkdir(parents=True, exist_ok=True)

    filename = "aether-next-config.json"
    return gui_src / filename


CONFIG_FILE = get_config_file_path()

# Logger for this module
logger = get_logger("config")

MODEL_CONFIG_KEYS = (
    "openai_model",
    "gatherer_model",
    "annotator_model",
    "ai_decomp_model",
    "single_analysis_model",
    "struct_creator_model",
    "index_agent_model",
)

# Keys for the grouped subagents config
SUBAGENT_KEYS = (
    "gatherer_model",
    "annotator_model",
    "ai_decomp_model",
    "single_analysis_model",
    "struct_creator_model",
    "index_agent_model",
)


class Subagents(BaseModel):
    model_config = {"populate_by_name": True}

    gatherer_model: str | None = Field("")
    annotator_model: str | None = Field("")
    ai_decomp_model: str | None = Field("")
    single_analysis_model: str | None = Field("")
    struct_creator_model: str | None = Field("")
    index_agent_model: str | None = Field("")


_DEFAULT_MODEL_LIST = {
    "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
    "OpenAI: gpt-oss-120b": "openai/gpt-oss-120b",
    "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct",
}


class AetherConfig(BaseModel):
    model_config = {"populate_by_name": True}

    # API / connection
    openai_api_key: str = Field("")
    openai_model: str = Field("qwen/qwen3-coder")
    openai_base_url: str = Field("https://openrouter.ai/api/v1")
    openai_extra_body: dict[str, object] = Field(default_factory=dict)
    mcp_server_url: str = Field("http://127.0.0.1:8744/sse")

    # Grouped per-component model overrides under `subagents`.
    # Empty string means "use openai_model"; resolved by validator.
    subagents: Subagents = Field(default_factory=lambda: Subagents.model_validate({}))

    # Limits / tuning
    max_iterations: Annotated[int, Field(gt=0)] = Field(5)
    prompt_token_warning: Annotated[int, Field(gt=0)] = Field(64000)
    annotator_max_tokens: Annotated[int, Field(gt=0)] = Field(30000)
    deobfuscator_max_tokens: Annotated[int, Field(gt=0)] = Field(16384)
    chatbot_max_tokens: Annotated[int, Field(gt=0)] = Field(65536)

    # Behaviour flags
    system_prompt_at_bottom: bool = Field(False)
    chatbot_idx_dialog: bool = Field(False)
    always_prompt_model: bool = Field(True)
    use_desc: bool = Field(True)
    use_comments: bool = Field(True)
    rename_vars: bool = Field(True)
    rename_funcs: bool = Field(True)
    rename_filter_enabled: bool = Field(True)
    comment_every_line: bool = Field(False)
    debug: bool = Field(False)

    # TLS / certs
    custom_ca_cert_path: str = Field("")
    client_cert_path: str = Field("")
    client_key_path: str = Field("")

    # Model catalogue
    model_list: dict[str, str] = Field(
        default_factory=lambda: dict(_DEFAULT_MODEL_LIST),
    )

    @field_validator("model_list")
    def validate_model_list(cls, v: dict[str, str]) -> dict[str, str]:
        if not v:
            raise ValueError("MODEL_LIST must not be empty")
        for display_name, model_id in v.items():
            if not display_name.strip():
                raise ValueError(f"MODEL_LIST: blank display name for model '{model_id}'")
            if not model_id.strip():
                raise ValueError(f"MODEL_LIST: blank model ID for display name '{display_name}'")
        return v

    @model_validator(mode="after")
    def resolve_subagents(self) -> AetherConfig:
        valid_ids = set(self.model_list.values())

        for key in SUBAGENT_KEYS:
            value = getattr(self.subagents, key)
            if not value:
                object.__setattr__(self.subagents, key, self.openai_model)
            elif value not in valid_ids:
                raise ValueError(f"{key.upper()}: '{value}' is not listed in MODEL_LIST")

        return self


def _write_config_file(config: AetherConfig) -> bool:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config.model_dump(), f, indent=2)
        return True
    except Exception as e:
        logger.error("Error saving config file: %s", e)
        return False


def load_config() -> AetherConfig:
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        logger.info("Config file not found or unreadable at %s, using defaults", CONFIG_FILE)
        raw = {}

    try:
        cfg = AetherConfig.model_validate(raw)
    except ValidationError as e:
        raise ValueError(f"Config validation error: {e}") from e

    try:
        if (not CONFIG_FILE.exists()) or (CONFIG_FILE.exists() and CONFIG_FILE.stat().st_size == 0):
            _write_config_file(cfg)
    except Exception as e:
        logger.error("Error writing default config file: %s", e)
    return cfg
