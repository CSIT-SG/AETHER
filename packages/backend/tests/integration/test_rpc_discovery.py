from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from aether_backend.utils.rpc_discovery import RPCRegistry
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

pytestmark = pytest.mark.asyncio


async def _list_rpc_connections_text(mcp_client: Client[StreamableHttpTransport]) -> str:
    response = await mcp_client.call_tool("list_rpc_connections")
    content = response.content
    if not content or content[0].type != "text":
        return ""
    return content[0].text


@pytest.mark.dependency(scope="package")
async def test_list_rpc_connections_includes_the_running_headless_instance(
    mcp_client: Client[StreamableHttpTransport],
    get_binary: Callable[..., Path],
) -> None:
    """The already-running headless IDA instance (started by the autouse
    `headless_ida` fixture) should be discoverable via `list_rpc_connections`
    without this test spinning up any service of its own.
    """
    bin_path = get_binary("basic")

    deadline = time.monotonic() + 15.0
    text = ""
    while time.monotonic() < deadline:
        text = await _list_rpc_connections_text(mcp_client)
        if text:
            break
        time.sleep(0.5)

    assert text, "list_rpc_connections returned no content within 15s"

    if bin_path.stem not in text:
        pytest.fail(
            f"list_rpc_connections did not mention {bin_path.stem!r}. "
            f"Raw response: {text!r} -- if the registered instance id isn't "
            "derived from the binary stem, update this assertion to match "
            "the real id scheme."
        )


@pytest.mark.dependency(scope="package")
async def test_detect_new_rpc(instance_ids: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry = RPCRegistry(directory=instance_ids)

    check_config_live = AsyncMock()
    monkeypatch.setattr(registry, "_check_config_live", check_config_live)

    listen_task = asyncio.create_task(registry._listen())

    try:
        async with asyncio.timeout(5):
            # give awatch a moment to start watching before triggering change
            await asyncio.sleep(0.1)

            file_path = instance_ids / "sample-99999999.json"
            file_path.write_text("test watcher")

            # poll until _check_config_live has actually been called
            while not check_config_live.await_count:
                await asyncio.sleep(0.05)
    finally:
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            pass

    check_config_live.assert_awaited_once_with(file_path)
