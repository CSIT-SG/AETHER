from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from aether_backend.utils.rpc_discovery import RPCRegistry

pytestmark = pytest.mark.asyncio


@pytest.mark.dependency(scope="package", name="test_detect_new_rpc")
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


@pytest.mark.dependency(scope="package", depends=["test_detect_new_rpc"])
async def test_detect_deleted_rpc(instance_ids: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = instance_ids / "sample-99999999.json"
    # file should already exist from test_detect_new_rpc, but don't rely on
    file_path.write_text("test watcher")

    registry = RPCRegistry(directory=instance_ids)

    check_config_live = AsyncMock()
    monkeypatch.setattr(registry, "_check_config_live", check_config_live)

    listen_task = asyncio.create_task(registry._listen())

    try:
        async with asyncio.timeout(5):
            await asyncio.sleep(0.1)

            file_path.unlink()

            while not check_config_live.await_count:
                await asyncio.sleep(0.05)
    finally:
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            pass

    check_config_live.assert_awaited_once_with(file_path)
