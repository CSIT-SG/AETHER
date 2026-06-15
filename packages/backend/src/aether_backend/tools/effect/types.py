from collections.abc import AsyncGenerator

from .models import Log, Progress, Return, Sleep

type Effect = Progress | Log | Sleep | Return
type Program = AsyncGenerator[Effect, None]
