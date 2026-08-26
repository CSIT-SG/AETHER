from typing import NotRequired, TypedDict


class EvaluateConfig(TypedDict):
    api_key: str
    base_url: NotRequired[str]
    model: NotRequired[str]
