from types import SimpleNamespace
from typing import Literal, TypedDict

type Theme = Literal["dark", "light"]

type ThemeColors = dict[str, str]


class ThemeState(TypedDict):
    theme: Theme | None
    colors: SimpleNamespace | None
