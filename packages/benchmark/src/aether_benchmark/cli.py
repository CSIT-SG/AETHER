from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, CliApp


class BenchmarkSettings(
    BaseSettings,
    cli_parse_args=True,
    cli_prog_name="aether_benchmark",
    cli_kebab_case=True,
    cli_implicit_flags=True,
    populate_by_name=True,
):
    """AETHER Benchmark - evaluate annotation quality against rubric."""

    idb: Path | None = Field(default=None, description="Path to the IDB/i64 file")
    doc: Path | None = Field(
        default=None, description="Path to the chatbot transcript markdown file"
    )
    rubric: Path = Field(description="Path to the rubric YAML file")
    api_key: str | None = Field(
        default_factory=lambda: os.environ.get("OPENROUTER_API_KEY"),
        description="OpenRouter/OpenAI API key (default: OPENROUTER_API_KEY env)",
    )
    model: str = Field(default="openai/gpt-5-mini", description="Model slug")
    base_url: str = Field(default="https://openrouter.ai/api/v1", description="API base URL")
    ida_dir: Path | None = Field(
        default_factory=lambda: Path(v) if (v := os.environ.get("IDADIR")) else None,
        description="IDA Pro installation directory (default: IDADIR env; only used for ida harness)",
    )
    verbose: bool = Field(default=False, description="Show detailed per-entry results", alias="v")
    json_output: bool = Field(
        default=False, alias="json", description="Print the benchmark result as JSON"
    )
    output: Path | None = Field(
        default=None, description="Write the benchmark result as JSON to this file", alias="o"
    )

    @model_validator(mode="after")
    def _api_key_required(self) -> Self:
        if not self.api_key:
            raise ValueError("--api-key is required (or set OPENROUTER_API_KEY)")
        return self

    @model_validator(mode="after")
    def _exactly_one_of_idb_doc(self) -> Self:
        if (self.idb is None) == (self.doc is None):
            raise ValueError("exactly one of --idb or --doc is required")
        return self

    @model_validator(mode="after")
    def _ida_dir_requires_idb(self) -> Self:
        if self.ida_dir is not None and self.idb is None:
            raise ValueError("--ida-dir may only be set when --idb is set")
        return self


class IdbTarget(BaseModel):
    name: Literal["idb"] = Field(default="idb")
    idb: Path
    ida_dir: Path


class DocTarget(BaseModel):
    name: Literal["doc"] = Field(default="doc")
    doc: Path


class BenchmarkConfig(BaseModel):
    target: IdbTarget | DocTarget
    rubric: Path
    api_key: str
    model: str
    base_url: str
    verbose: bool
    json_output: bool
    output: Path | None


def get_config() -> BenchmarkConfig:
    """Run the CLI, validate, and return an arg set."""
    raw = CliApp.run(BenchmarkSettings)

    target: IdbTarget | DocTarget
    if raw.idb is not None:
        assert raw.ida_dir is not None
        target = IdbTarget(idb=raw.idb, ida_dir=raw.ida_dir)
    else:
        assert raw.doc is not None
        target = DocTarget(doc=raw.doc)

    assert raw.api_key is not None
    return BenchmarkConfig(
        target=target,
        rubric=raw.rubric,
        api_key=raw.api_key,
        model=raw.model,
        base_url=raw.base_url,
        verbose=raw.verbose,
        json_output=raw.json_output,
        output=raw.output,
    )
