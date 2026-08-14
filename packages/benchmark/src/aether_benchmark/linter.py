import os
import sys

import yaml
from pydantic import BaseModel, Field, ValidationError


class Criterion(BaseModel):
    description: str


class RubricEntry(BaseModel):
    id: str
    description: str | None = None
    function_address: str = Field(..., pattern=r"^0x[0-9A-Fa-f]+$")
    weight: float = Field(..., gt=0)
    criteria: list[Criterion]


class RubricsSchema(BaseModel):
    name: str
    version: str
    description: str | None = None
    rubrics: list[RubricEntry]


def lint_rubric(source: str | os.PathLike[str]):
    """Validate rubric YAML from either a file path or raw YAML text.

    Returns the validated RubricsSchema instance on success.
    Raises ValidationError or YAML parsing errors on failure.
    """
    if isinstance(source, (str, os.PathLike)) and (
        isinstance(source, os.PathLike) or os.path.exists(str(source))
    ):
        with open(source, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    else:
        data = yaml.safe_load(str(source))

    if data is None:
        raise ValidationError.from_exception_data(
            title="Rubric validation",
            line_errors=[],
        )

    return RubricsSchema(**data)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python linter.py <path_to_yaml_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        lint_rubric(file_path)
        print(f"Success: {file_path} is valid.")
        sys.exit(0)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except ValidationError as e:
        print(f"Validation Error in '{file_path}':")
        print(e)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"YAML Syntax Error in '{file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected Error: {e}")
        sys.exit(1)
