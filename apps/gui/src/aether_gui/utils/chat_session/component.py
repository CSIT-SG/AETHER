import atexit
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aether_gui.utils.chat_session.models import Message
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.compacting_session import CompactingSession, get_compacting_agent
from aether_utils.data_dir import get_data_dir


class ChatSession:
    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.chat_session = CompactingSession(summarizer=get_compacting_agent())

        rpc_id = get_rpc_id()
        if rpc_id is None:
            raise RuntimeError("RPC server does not exist")

        _data_dir = get_data_dir("gui", Path("chat_sessions"))
        _inode = _data_dir / f"{rpc_id}.log"
        _inode.touch()

        self.log_path = _inode
        self._io_executor = ThreadPoolExecutor(max_workers=1)

        atexit.register(self.__exit__, None, None, None)

    def _write_line(self, line: str) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def add_message(self, msg: Message) -> None:
        self.messages.append(msg)
        self._io_executor.submit(self._write_line, f"{msg.role}: {msg.content}\n")

    def append_to_last_message(self, diff: str) -> None:
        self.messages[-1].content += diff
        self._io_executor.submit(self._write_line, diff)

    def __exit__(self, exc_type, exc, tb):
        self._io_executor.shutdown(wait=True)
