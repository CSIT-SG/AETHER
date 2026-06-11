from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import sys

class MessageRole(Enum):
    """Enum for Message Roles"""
    USER = "User"
    AETHER = "Aether"

@dataclass
class Message:
    """Message modal for all layers"""

    id: str
    role: str
    content: str
    timestamp: datetime

    @property
    def formatted_timestamp(self) -> str:
        if sys.platform == "win32":
            return self.timestamp.strftime("%#I:%M %p")
        else:
            return self.timestamp.strftime("%-I:%M %p")

