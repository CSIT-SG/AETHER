from ..messages.Messages import Message


class ChatSession:
    def __init__(self) -> None:
        self.messages: list[Message] = []

    def add_message(self, msg: Message) -> None:
        self.messages.append(msg)

