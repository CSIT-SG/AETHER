from collections.abc import AsyncGenerator

from .models import Progress, Return, Sleep

type Effect = Progress | Sleep | Return
type Program = AsyncGenerator[Effect, None]
