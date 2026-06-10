from datetime import datetime

from PySide6.QtWidgets import QApplication

from aether_gui.features.chatbot.components.messages.components import Message
from aether_gui.features.chatbot.components.messages.message_bubble import MessageBubble

app = QApplication([])

msg = Message(
    role="User",
    content="Hello world",
    timestamp=datetime.now(),
)

widget = MessageBubble(msg)
widget.resize(500, 300)
widget.show()

app.exec()
