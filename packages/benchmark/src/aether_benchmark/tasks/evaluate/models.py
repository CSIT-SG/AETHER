from typing import TypedDict


class CriterionResult(TypedDict):
    """Result of evaluating a single criterion."""
    passed: bool
    reasoning: str
