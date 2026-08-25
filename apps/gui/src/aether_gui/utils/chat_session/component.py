import asyncio
import shelve
from pathlib import Path
from typing import cast

from aether_gui.utils.chat_session.models import Message
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.compacting_session import CompactingSession, get_compacting_agent
from aether_utils.data_dir import get_data_dir
from agents import TResponseInputItem

KEY = "messages"


class ChatSession:
    def __init__(self) -> None:
        rpc_id = get_rpc_id()
        if rpc_id is None:
            raise RuntimeError("No rpc_id available yet")

        _data_dir = get_data_dir("gui", Path("chat_sessions"))
        self._shelf = shelve.open(_data_dir / rpc_id, writeback=True)
        self._shelf.setdefault(KEY, [])

        self.chat_session = CompactingSession(summarizer=get_compacting_agent())

        asyncio.run(self._load_from_shelf())

    async def _load_from_shelf(self) -> None:
        """Replay any previously persisted messages into the in-memory agent session."""
        messages: list[Message] = self._shelf[KEY]
        if not messages:
            return

        items = cast(
            list[TResponseInputItem],
            [{"role": msg.role, "content": msg.content} for msg in messages],
        )
        await self.chat_session.add_items(items)

    @property
    def messages(self) -> list[Message]:
        return self._shelf[KEY]

    def add_message(self, msg: Message) -> None:
        self._shelf[KEY].append(msg)
        self._shelf.sync()

    def append_to_last_message(self, msg: str) -> None:
        self._shelf[KEY][-1].content += msg
        self._shelf.sync()

    def close(self) -> None:
        self._shelf.close()

    def __enter__(self) -> "ChatSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
