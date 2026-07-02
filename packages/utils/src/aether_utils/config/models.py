from typing import Self

from pydantic import BaseModel, Field, model_validator


class ProviderModel(BaseModel):
    gateway_url: str = Field(..., description="The base URL for the provider's API gateway.")
    api_key: str = Field("", description="The API key for the provider.")
    models: dict[str, str] = Field(
        default_factory=dict,
        description="A mapping of friendly names to model ids for this provider.",
    )
    default_model: str = Field(..., description="Friendly name of default model to fall back to.")
    extra_body: dict[str, object] | None = Field(
        default_factory=dict,
        description=(
            "Any extra body parameters to include in requests to this provider, "
            'e.g. {"reasoning": {"effort": "high"}} or {"transforms": ["middle-out"]}.'
        ),
        examples=[{"reasoning": {"effort": "high"}}],
    )

    @model_validator(mode="after")
    def resolve_default_model(self) -> Self:
        keys = set(self.models.keys())
        if self.default_model not in keys:
            raise ValueError(f"Default model must be listed in the models provided: {keys}")
        return self


class SubagentsModel(BaseModel):
    gatherer_model: str | None = Field(
        default=None, description="Model override for the gatherer subagent."
    )
    annotator_model: str | None = Field(
        default=None, description="Model override for the annotator subagent."
    )
    ai_decomp_model: str | None = Field(
        default=None, description="Model override for the AI decomposition subagent."
    )
    single_analysis_model: str | None = Field(
        default=None, description="Model override for the single analysis subagent."
    )
    struct_creator_model: str | None = Field(
        default=None, description="Model override for the structure creator subagent."
    )
    index_agent_model: str | None = Field(
        default=None, description="Model override for the index agent subagent."
    )


class FeaturesModel(BaseModel):
    annotator: dict[str, object] | None = Field(
        default=None,
        description="Feature flags and parameters for the annotator component.",
    )
    deobfuscator: dict[str, object] | None = Field(
        default=None,
        description="Feature flags and parameters for the deobfuscator component.",
    )
    chatbot: dict[str, object] | None = Field(
        default=None, description="Feature flags and parameters for the chatbot component."
    )
    gatherer: dict[str, object] | None = Field(
        default=None, description="Feature flags and parameters for the gatherer component."
    )
    ai_decomp: dict[str, object] | None = Field(
        default=None,
        description="Feature flags and parameters for the AI decomposition component.",
    )


class TlsConfigModel(BaseModel):
    client_cert_path: str = Field(
        "",
        description="Path to the client certificate for mutual TLS authentication, if required by the provider.",
    )
    client_key_path: str = Field(
        "",
        description="Path to the client private key for mutual TLS authentication, if required by the provider.",
    )


class ConfigModel(BaseModel):
    model_config = {"populate_by_name": True}

    provider: ProviderModel = Field(..., description="The language model provider configuration.")
    subagents: SubagentsModel | None = Field(
        default=None, description="Model overrides for specific subagents."
    )
    features: FeaturesModel | None = Field(
        default=None, description="Feature flags and parameters for various components."
    )
    debug: bool | None = Field(
        default=None,
        description="Whether to enable debug mode, which may include more verbose logging and additional output for debugging purposes.",
    )
    backup: bool | None = Field(
        default=True, description="Whether to enable backups before performing destructive actions"
    )
    experimental: bool | None = Field(
        default=None,
        description="Whether to enable experimental features, which may be unstable or in development.",
    )
    tls: TlsConfigModel | None = Field(
        default=None, description="TLS configuration for secure connections."
    )

    @model_validator(mode="after")
    def resolve_subagents(self) -> Self:
        # if subagents is provided, ensure all fields are valid provider models

        subagents = self.subagents
        provider = self.provider

        if not subagents:
            return self

        provider_models = set(provider.models.keys())
        for field_name, subagent_model in subagents.model_dump().items():
            if subagent_model is not None and subagent_model not in provider_models:
                raise ValueError(
                    f"Subagent '{field_name}' has model '{subagent_model}' which is not in the provider's model list."
                )
        return self
