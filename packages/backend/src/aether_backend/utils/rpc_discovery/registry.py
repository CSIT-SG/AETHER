import asyncio
import json
from contextlib import suppress
from pathlib import Path
from typing import Any

from aether_rpc.registry import RPCFileRegistry
from aether_utils.data_dir import get_data_dir
from aether_utils.logger import get_logger
from watchfiles import Change, awatch

from .connection import RpcConnectionEntry, connect_with_backoff, ping, safe_close
from .constants import DISCOVERY_REFRESH_INTERVAL


class RPCRegistry:
    """
    Maps RPC id -> live RPyC connection root object.
    """

    def __init__(
        self,
        directory: Path = get_data_dir("rpc"),
        refresh_interval: int = DISCOVERY_REFRESH_INTERVAL,
    ) -> None:
        self._directory = directory
        self._refresh_interval = refresh_interval

        self._entries: dict[str, RpcConnectionEntry] = {}
        self._lock = asyncio.Lock()

        self._heartbeat_task: asyncio.Task[None] | None = None
        self._file_watching_task: asyncio.Task[None] | None = None
        self._started = False
        self._logger = get_logger("rpc-registry")

    # Lifecycle

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name="rpc-registry-heartbeat",
        )
        self._file_watching_task = asyncio.create_task(
            self._listen(),
            name="rpc-registry-file-watcher",
        )

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None

        await self._close_all()

    # Public accessors

    async def get(self, rpc_id: str) -> Any | None:
        async with self._lock:
            entry = self._entries.get(rpc_id)
            return entry.root if entry else None

    async def has(self, rpc_id: str) -> bool:
        async with self._lock:
            return rpc_id in self._entries

    async def ids(self) -> list[str]:
        async with self._lock:
            return sorted(self._entries)

    async def all(self) -> dict[str, Any]:
        async with self._lock:
            return {k: v.root for k, v in self._entries.items()}

    # Heartbeat
    async def _heartbeat_loop(self) -> None:
        configs = self._load_configs()
        while True:
            try:
                #check if all configs are live
                for rpc_id, (_, path) in configs.items():
                    await self._check_config_live(path)
                self._logger.info("Current active configs: %s", self._entries.keys())
                self._logger.debug("RPC registry heartbeat check complete")
                await asyncio.sleep(self._refresh_interval)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("RPC registry heartbeat error")

    # Watcher
    async def _listen(self) -> None:
        # initial scan when server first starts
        # Catches already opened IDA instances
        entry_memory = self._load_configs()
        if entry_memory:
            #check if config files are live
            for rpc_id, (_, path) in entry_memory.items():
                await self._check_config_live(path)
            self._logger.info("Existing RPC Configs: %s", self._entries.keys())

        async for changes in awatch(self._directory):
            for change_type, change_path in changes:
                path_obj = Path(change_path)
                self._logger.debug("memdump %r", entry_memory)
                self._logger.debug("RPC registry watcher detected changes at: %r action: %r", change_path, change_type)
                if change_type == Change.added:
                     entry_memory = self._load_configs()
                elif change_type == Change.deleted:
                    async with self._lock:
                        rpc_id = next(k for k, v in entry_memory.items() if v[1] == path_obj)
                        self._entries.pop(rpc_id)
                        entry_memory.pop(rpc_id)
                await self._check_config_live(path_obj)

    # Internal helpers

    def _load_configs(self) -> dict[str, tuple[int, Path]]:  # {rpc_id: (port, path)}
        """Returns {rpc_id: (port, path)}"""
        result = {}
        for path in self._directory.glob("*.json"):
            if entry := RPCFileRegistry.load(path):
                result[entry.id] = (entry.port, path)
        return result

    async def _check_config_live(self, path: Path)-> bool:
        """checks if the config file is live

        Takes in path to json file, reads contents.

        returns true if it is live, false if not
        """
        with path.open(mode="r") as f:
            data = json.load(f)
        rpc_id: str = data.get("id")
        port: int = data.get("port")
        exists = await connect_with_backoff(rpc_id, port)
        if exists:
            async with self._lock:
                self._entries[rpc_id] = exists
        return bool(exists)

    async def _close_all(self) -> None:
        async with self._lock:
            entries = self._entries
            self._entries = {}
        for entry in entries.values():
            safe_close(entry.conn)
