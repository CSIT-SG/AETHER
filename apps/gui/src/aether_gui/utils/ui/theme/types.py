from typing import Literal, TypedDict

type Theme = Literal["dark", "light"]


class ThemeColors(TypedDict):
    window: str  # Window/background color
    base: str  # Base input/background color
    text: str  # Primary text color
    mid: str  # Mid-tone separator/border color
    button: str  # Button background color
    highlight: str  # Selection/highlight color
