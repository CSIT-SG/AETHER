from dataclasses import dataclass
from datetime import datetime

@dataclass
class Message:
    """Message modal for all layers"""
    role: str
    content: str
    timestamp: datetime
