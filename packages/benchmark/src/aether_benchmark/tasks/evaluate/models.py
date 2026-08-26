from typing import NotRequired, TypedDict


class CriterionResult(TypedDict):
    """Result of evaluating a single criterion."""

    passed: bool
    reasoning: str


class EvaluateRubric(TypedDict):
    name: NotRequired[str]
    description: NotRequired[str]
    criteria: NotRequired[list[str]]
