"""Buffers subtool progress from the MCP progress channel"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from aether_gui.utils.mcp import MCPClient
from aether_gui.utils.mcp.types import ServerProgressMessage

from .types import _SENTINEL


class SubtoolProgressBuffer:
    """Collects subtool traces emitted via MCP progress notifications"""

    def __init__(self, mcp_client: MCPClient) -> None:
        self._queue: asyncio.Queue[str | object] = asyncio.Queue()
        self._subscription = mcp_client.subscribe_progress(self._on_progress)
        self._closed = False

    async def _on_progress(self, event: ServerProgressMessage) -> None:
        """Listener: enqueue each subtool message"""
        if event.message and not self._closed:
            await self._queue.put(event.message)

    async def traces(self) -> AsyncIterator[str]:
        """Return all currently buffered traces until the buffer is closed."""
        while not self._closed:
            message = await self._queue.get()
            if message is _SENTINEL:
                return
            yield message  # type: ignore[misc]

    def close(self) -> None:
        """Stop the trace stream and unsubscribe from the progress channel."""
        if self._closed:
            return
        self._closed = True
        self._queue.put_nowait(_SENTINEL)
        self._subscription.close()
