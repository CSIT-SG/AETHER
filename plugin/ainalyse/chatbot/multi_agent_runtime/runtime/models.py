from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Message:
    sender: str
    recipient: str
    content: Any
    topic: str = "message"
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class PublishedEvent:
    key: str
    value: Any
    publisher: str
    created_at: datetime = field(default_factory=utc_now)
