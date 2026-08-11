from pydantic import BaseModel, Field


class RubricEntry(BaseModel):
    name: str
    description: str | None = None
    weight: float = Field(default=1.0, gt=0)
    criteria: list[str]


class RubricsSchema(BaseModel):
    name: str
    version: str
    description: str | None = None
    rubrics: list[RubricEntry]
