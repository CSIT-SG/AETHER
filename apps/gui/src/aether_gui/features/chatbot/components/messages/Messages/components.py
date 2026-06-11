from dataclasses import dataclass
from datetime import datetime
from enum import Enum

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


