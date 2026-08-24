from aether_gui.utils.chat_session.models import Message
from aether_utils.compacting_session import CompactingSession, get_compacting_agent


class ChatSession:
    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.chat_session = CompactingSession(summarizer=get_compacting_agent())

    def add_message(self, msg: Message) -> None:
        self.messages.append(msg)

    def append_to_last_message(self, msg: str) -> None:
        self.messages[-1].content += msg
