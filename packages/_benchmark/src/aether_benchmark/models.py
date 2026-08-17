"""Pydantic models for the AETHER benchmark rubric and evaluation results."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, Field, model_validator


class Feature(StrEnum):
    """AETHER features that can be benchmarked."""

    ANNOTATION = "annotation"
    STRUCT_CREATION = "struct_creation"
    CHATBOT = "chatbot"
    DEOBFUSCATION = "deobfuscation"


class Difficulty(StrEnum):
    """Difficulty tiers for benchmark tasks."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


# ── Rubric models ──────────────────────────────────────────────────────────────


class Criterion(BaseModel):
    """A single checkable item within a rubric entry."""

    id: str = Field(description="Unique identifier for this criterion within the rubric entry.")
    description: str = Field(description="Human-readable description of what to check.")


class RubricEntry(BaseModel):
    """One evaluation task in the benchmark."""

    id: str = Field(description="Unique identifier for this rubric entry.")
    feature: Feature = Field(description="The AETHER feature being tested.")
    difficulty: Difficulty = Field(description="Difficulty tier of this task.")
    description: str = Field(description="Human-readable description of the evaluation task.")
    function_address: str = Field(
        description="Hex address of the function to evaluate (e.g. '0x14E373').",
        examples=["0x14E373"],
    )
    weight: float = Field(
        default=1.0,
        ge=0.0,
        description="Relative weight of this entry when computing overall scores.",
    )
    criteria: list[Criterion] = Field(
        min_length=1, description="List of criteria to evaluate for this entry."
    )


class BenchmarkDef(BaseModel):
    """Top-level benchmark definition, parsed from a YAML file."""

    name: str = Field(description="Name of the benchmark suite.")
    version: str = Field(description="Semantic version of the benchmark definition.")
    description: str = Field(description="Short description of the benchmark's scope.")
    rubrics: list[RubricEntry] = Field(
        min_length=1, description="List of rubric entries to evaluate."
    )

    @model_validator(mode="after")
    def check_unique_ids(self) -> Self:
        ids = [r.id for r in self.rubrics]
        if len(ids) != len(set(ids)):
            raise ValueError(f"Duplicate rubric entry IDs found: {ids}")
        for entry in self.rubrics:
            cids = [c.id for c in entry.criteria]
            if len(cids) != len(set(cids)):
                raise ValueError(f"Duplicate criterion IDs in rubric entry '{entry.id}': {cids}")
        return self


# ── Evaluation result models ────────────────────────────────────────────────────


class CriterionResult(BaseModel):
    """Result of evaluating a single criterion."""

    criterion_id: str = Field(description="ID of the criterion this result corresponds to.")
    passed: bool = Field(description="Whether the criterion was satisfied.")
    reasoning: str = Field(description="Brief explanation of why this passed or failed.")


class RubricEvalResult(BaseModel):
    """Structured output from the LLM for one rubric entry."""

    passed: bool = Field(description="Overall pass/fail for the rubric entry.")
    criterion_results: list[CriterionResult] = Field(
        description="Per-criterion evaluation results."
    )
    summary: str = Field(description="Short narrative summary of the evaluation findings.")


class RubricScore(BaseModel):
    """Computed score for one rubric entry."""

    rubric_id: str = Field(description="ID of the rubric entry.")
    raw_score: float = Field(ge=0.0, le=1.0, description="Fraction of criteria passed (0.0-1.0).")
    weighted_score: float = Field(
        ge=0.0, description="Raw score multiplied by the rubric entry's weight."
    )
    passed: bool = Field(description="Whether the entry was considered passing.")
    detail: RubricEvalResult = Field(description="Full evaluation result from the LLM.")


class BenchmarkResult(BaseModel):
    """Aggregated results for the entire benchmark run."""

    benchmark_name: str = Field(description="Name of the benchmark suite.")
    version: str = Field(description="Version of the benchmark definition.")
    overall_score: float = Field(ge=0.0, le=100.0, description="Overall weighted percentage score.")
    tier_breakdown: dict[str, float] = Field(
        description="Mean score per difficulty tier: {easy: %, medium: %, hard: %}."
    )
    feature_matrix: dict[str, float] = Field(
        description="Mean score per feature: {annotation: %, struct_creation: %, ...}."
    )
    per_entry: list[RubricScore] = Field(description="Individual scores for each rubric entry.")
    total_entries: int = Field(description="Total number of rubric entries evaluated.")
    passed_entries: int = Field(description="Number of rubric entries that passed.")
