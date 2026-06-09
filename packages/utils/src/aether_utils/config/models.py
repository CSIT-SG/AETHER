from pydantic import BaseModel, Field, field_validator, model_validator
from .constants import SUBAGENT_KEYS, DEFAULT_MODEL_LIST

from typing import Annotated, Self


class Subagents(BaseModel):
    model_config = {"populate_by_name": True}

    gatherer_model: str | None = Field("")
    annotator_model: str | None = Field("")
    ai_decomp_model: str | None = Field("")
    single_analysis_model: str | None = Field("")
    struct_creator_model: str | None = Field("")
    index_agent_model: str | None = Field("")


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
        default_factory=lambda: dict(DEFAULT_MODEL_LIST),
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
    def resolve_subagents(self) -> Self:
        valid_ids = set(self.model_list.values())

        for key in SUBAGENT_KEYS:
            value = getattr(self.subagents, key)
            if not value:
                object.__setattr__(self.subagents, key, self.openai_model)
            elif value not in valid_ids:
                raise ValueError(f"{key.upper()}: '{value}' is not listed in MODEL_LIST")

        return self
