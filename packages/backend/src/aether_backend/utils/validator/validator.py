from typing import Any, TypeVar

from pydantic import BaseModel

M = TypeVar("M", bound=BaseModel)


def validate[M: BaseModel](model: type[M], value: Any) -> M:
    """Validate a value against a pydantic model, raising a ValidationError if invalid."""

    return model.model_validate(value)
