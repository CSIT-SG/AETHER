from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    verdict: bool
    detail: str
    status_code: int | None = None


type ResultCallback = Callable[[CheckResult], None]
type CheckTask = Callable[[str, ResultCallback], None]
