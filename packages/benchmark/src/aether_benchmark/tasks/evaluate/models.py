from typing import Literal, TypedDict

from pydantic import BaseModel, Field


class CriterionResult(TypedDict):
    """Result of evaluating a single criterion."""

    passed: bool
    reasoning: str


# errors as values


class _SuccessfulAgentRunCriterionResult(TypedDict):
    """Result of a successful agent run."""

    success: Literal[True]
    data: CriterionResult


class _FailedAgentRunCriterionResult(TypedDict):
    """Result of a failed agent run."""

    success: Literal[False]
    error: str


type AgentRunResult = _SuccessfulAgentRunCriterionResult | _FailedAgentRunCriterionResult


# create a new class that extends BenchmarkSchema and adds the results of the evaluation


class CriterionWithResult(BaseModel):
    criterion: str
    result: AgentRunResult


class RubricEntryWithResults(BaseModel):
    name: str
    description: str | None = None
    weight: float = Field(default=1.0, gt=0)
    criteria: list[CriterionWithResult]


class BenchmarkSchemaWithResults(BaseModel):
    name: str
    version: str | None = None
    description: str | None = None
    rubrics: list[RubricEntryWithResults]
