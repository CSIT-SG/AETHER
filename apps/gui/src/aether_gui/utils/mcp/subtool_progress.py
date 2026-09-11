"""Buffers live subtool progress from the MCP progress channel"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from aether_gui.utils.mcp import MCPClient
from aether_gui.utils.mcp.types import ServerProgressMessage


class SubtoolProgressBuffer:
    """Collects live subtool traces emitted via MCP progress notifications"""

    def __init__(self, mcp_client: MCPClient) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._subscription = mcp_client.subscribe_logs(self._on_progress)
        self._closed = False

    async def _on_progress(self, event: ServerProgressMessage) -> None:
        """Listener: enqueue each subtool message"""
        if event.message:
            await self._queue.put(event.message)

    async def traces(self) -> AsyncIterator[str]:
        """Return all currently buffered traces without awaiting"""
        while not self._closed:
            try:
                message = await self._queue.get()
            except asyncio.QueueEmpty:
                continue
            yield message
        # Drain any remaining after close
        while not self._queue.empty():
            yield self._queue.get_nowait()

    def close(self) -> None:
        """Unsubscribe from the progress channel"""
        self._subscription.close()
