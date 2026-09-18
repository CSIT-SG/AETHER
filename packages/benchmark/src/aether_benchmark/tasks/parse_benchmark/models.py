from aether_utils.get_version import get_version
from pydantic import BaseModel, Field, model_validator


class RubricEntry(BaseModel):
    name: str
    description: str | None = None
    weight: float = Field(default=1.0, gt=0)
    criteria: list[str]


class BenchmarkSchema(BaseModel):
    name: str
    version: str
    description: str | None = None
    rubrics: list[RubricEntry]

    @model_validator(mode="after")
    def _check_schema_version(self) -> "BenchmarkSchema":
        package_version = get_version()
        if package_version == "unknown":
            return self

        rubric_major = self.version.split(".", 1)[0]
        package_major = package_version.split(".", 1)[0]
        if rubric_major != package_major:
            raise ValueError(
                f"Rubric version '{self.version}' targets major version {rubric_major}, "
                f"but aether_benchmark is version {package_version} (major {package_major}). "
                "Update the rubric's `version` field to match, or use a matching aether_benchmark release."
            )
        return self
