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
        self._started = False
        self._logger = get_logger("rpc-registry")

    # Lifecycle

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._heartbeat_task = asyncio.create_task(
            #self._heartbeat_loop(),
            self._listen(),
            name="rpc-registry-heartbeat",
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
        while True:
            try:
                await self._check_connections(self._directory)
                self._logger.debug("RPC registry heartbeat check complete")
                await asyncio.sleep(self._refresh_interval)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("RPC registry heartbeat error")

    # Watcher
    async def _listen(self) -> None:
        initial_config = self._load_configs()
        self._logger.info(f"Existing RPC Configs: {initial_config.keys()}")
        async for changes in awatch(self._directory):
            for change_type, change_path in changes:
                self._logger.info(f"changed path: {change_path} change_type: {change_type}")
                if change_type == Change.added or change_type == Change.deleted:
                    self._logger.debug("RPC registry watcher detected changes at: %r", change_path)
                    await self._check_connections(change_path)


    async def _check_connections(self, file_path: str | Path) -> None:
        # ping all connections concurrently
        self._logger.debug("RPC registry checking connections due to change at: %r", file_path)
        async with self._lock:
            snapshot = dict(self._entries)
            self._logger.debug(f"GIGANIGGA SNAPSHOT {snapshot}")
        with open(file_path) as f:
            data = json.load(f)
            self._logger.debug(f"GIGANIGGA {data}")
        key = data.get("id")
        self._logger.debug(f"GIGANIGGA KEY {key}")
        ping_tasks = {
            rpc_id: asyncio.create_task(ping(entry))
            for rpc_id, entry in snapshot.items()
            if rpc_id == key
        }
        ping_results = await asyncio.gather(*ping_tasks.values(), return_exceptions=True)

        # check for dead connections and new configs
        configs = self._load_configs()
        live_ids = set(configs)

        to_reconnect: list[tuple[str, int]] = []
        async with self._lock:
            for rpc_id, ok in zip(ping_tasks, ping_results, strict=True):
                if ok is True:
                    if rpc_id not in live_ids:
                        self._logger.info("RPC service %r decommissioned (config removed)", rpc_id)
                        safe_close(snapshot[rpc_id].conn)
                        self._entries.pop(rpc_id, None)
                    # in any case, we don't need to reconnect
                    continue

                # connection is dead or ping failed, so we remove it from the registry
                safe_close(snapshot[rpc_id].conn)
                self._entries.pop(rpc_id, None)

                # we queue a reconnect if the config still exists
                if rpc_id in live_ids:
                    self._logger.info(rpc_id)
                    port, _ = configs[rpc_id]
                    to_reconnect.append((rpc_id, port))
                else:
                    self._logger.info("RPC service %r removed (config gone)", rpc_id)

            # we found new configs that we don't have connections for, so we queue them for reconnect
            for rpc_id in live_ids - set(self._entries) - {r for r, _ in to_reconnect}:
                self._logger.info("RPC service %r discovered (new config)", rpc_id)
                port, _ = configs[rpc_id]
                to_reconnect.append((rpc_id, port))

        if not to_reconnect:
            return

        # reconnect all queued connections concurrently
        new_entries = await asyncio.gather(
            *[connect_with_backoff(rpc_id, port) for rpc_id, port in to_reconnect],
            return_exceptions=False,
        )
        # update the registry with the new connections, removing any zombies that failed to reconnect
        async with self._lock:
            for (rpc_id, _), entry in zip(to_reconnect, new_entries, strict=True):
                if entry is not None:
                    self._entries[entry.rpc_id] = entry
                else:
                    self._logger.warning("RPC service %r unreachable — removing config", rpc_id)
                    _, path = configs[rpc_id]
                    path.unlink(missing_ok=True)

    # Internal helpers

    def _load_configs(self) -> dict[str, tuple[int, Path]]:  # {rpc_id: (port, path)}
        """Returns {rpc_id: (port, path)}"""
        result = {}
        for path in self._directory.glob("*.json"):
            if entry := RPCFileRegistry.load(path):
                result[entry.id] = (entry.port, path)
        return result

    async def _close_all(self) -> None:
        async with self._lock:
            entries = self._entries
            self._entries = {}
        for entry in entries.values():
            safe_close(entry.conn)
