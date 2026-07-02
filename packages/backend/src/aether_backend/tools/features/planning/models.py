from typing import Any, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from .utils import ObjectiveStatus, PlanStatus, new_id, now


class TimestampedModel(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    created_at: AwareDatetime = Field(default_factory=now)
    updated_at: AwareDatetime = Field(default_factory=now)

    _initialized: bool = PrivateAttr(default=False)

    def model_post_init(self, _context: Any) -> None:
        self._initialized = True

    @model_validator(mode='after')
    def _auto_update_timestamp(self) -> Self:
        if self._initialized:
            object.__setattr__(self, 'updated_at', now())
        return self


class ObjectiveModel(TimestampedModel):
    id: str = Field(default_factory=new_id, description="Server-generated unique id.")
    text: str = Field(..., description="Text description of the objective.")
    status: ObjectiveStatus = Field(default=ObjectiveStatus.PENDING, description="Current status.")



class PlanModel(TimestampedModel):
    id: str = Field(default_factory=new_id, description="Server-generated unique id.")
    title: str = Field(..., description="Title of the plan.")
    description: str = Field(default="", description="Detailed description of the plan.")
    status: PlanStatus = Field(default=PlanStatus.ACTIVE, description="Current status.")
    objectives: list[ObjectiveModel] = Field(
        default_factory=list, description="Objectives for the plan."
    )

