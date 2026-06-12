import asyncio
import json
from contextlib import suppress
from pathlib import Path
from typing import Any

from aether_utils.data_dir import get_data_dir
from aether_utils.logger import get_logger

from .connection import RpcConnectionEntry, connect_with_backoff, ping, safe_close


class RpcRegistry:
    """
    Maps RPC id → live RPyC connection root object.

    Each JSON file under *directory* must contain at least::

        { "id": "service_name", "port": 12345 }

    * **Parallel connect** - all services in a refresh cycle are connected
      concurrently via ``asyncio.gather``.
    * **Exponential back-off with jitter** - per-service retries follow
      a capped, jittered exponential schedule so thundering-herd spikes are
      avoided on restarts.
    * **Heartbeat with per-connection ping** - dead connections are detected
      and replaced individually without tearing down healthy peers.
    * **Graceful lifecycle** - ``start`` / ``stop`` are safe to call more than
      once; cancellation is handled cleanly.
    * **Thread-safe reads** - all public accessors acquire the asyncio lock
      so callers in concurrent coroutines never see a half-updated map.
    """

    def __init__(
        self,
        directory: Path = get_data_dir("rpc"),
        refresh_interval: int = 60,
    ) -> None:
        self._directory = directory
        self._refresh_interval = refresh_interval

        self._entries: dict[str, RpcConnectionEntry] = {}
        self._lock = asyncio.Lock()

        self._heartbeat_task: asyncio.Task[None] | None = None
        self._started = False
        self._logger = get_logger("rpc-registry")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        await self.refresh()
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
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

    # ------------------------------------------------------------------
    # Public accessors (all async to keep the lock contract uniform)
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Refresh - full rebuild, all services connected in parallel
    # ------------------------------------------------------------------

    async def refresh(self) -> None:
        """
        Re-read JSON configs and (re)connect every service in parallel.
        Services that fail all retries are omitted from the live map; the
        previously healthy connections remain in place until the new map
        is swapped in atomically.
        """
        configs = self._load_configs()
        if not configs:
            self._logger.warning("No RPC config files found in %s", self._directory)

        tasks = [connect_with_backoff(cfg["id"], cfg["port"]) for cfg in configs]

        results: list[RpcConnectionEntry | None] = await asyncio.gather(
            *tasks, return_exceptions=False
        )

        new_entries: dict[str, RpcConnectionEntry] = {}
        for entry in results:
            if entry is not None:
                new_entries[entry.rpc_id] = entry

        async with self._lock:
            old_entries = self._entries
            self._entries = new_entries

        self._close_stale(old_entries, new_entries)

        self._logger.info(
            "RPC registry refreshed: %d/%d services connected %s",
            len(new_entries),
            len(configs),
            sorted(new_entries),
        )

    # ------------------------------------------------------------------
    # Heartbeat - ping each live connection, replace dead ones
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._refresh_interval)
                await self._check_connections()
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("RPC registry heartbeat error")

    async def _check_connections(self) -> None:
        """
        Ping every live connection concurrently.  Dead connections are
        reconnected (with back-off) individually so healthy peers are
        unaffected.
        """
        async with self._lock:
            snapshot = dict(self._entries)

        dead: list[RpcConnectionEntry] = []
        ping_tasks = {
            rpc_id: asyncio.create_task(ping(entry)) for rpc_id, entry in snapshot.items()
        }
        ping_results = await asyncio.gather(*ping_tasks.values(), return_exceptions=True)

        for rpc_id, ok in zip(ping_tasks, ping_results, strict=True):
            alive = ok is True  # exceptions count as dead
            if not alive:
                self._logger.warning("RPC service %r is unresponsive; will reconnect", rpc_id)
                dead.append(snapshot[rpc_id])

        if not dead:
            return

        reconnect_tasks = [connect_with_backoff(e.rpc_id, e.port) for e in dead]
        new_entries_list: list[RpcConnectionEntry | None] = await asyncio.gather(
            *reconnect_tasks, return_exceptions=False
        )

        async with self._lock:
            for old_entry, new_entry in zip(dead, new_entries_list, strict=False):
                safe_close(old_entry.conn)
                if new_entry is not None:
                    self._entries[new_entry.rpc_id] = new_entry
                else:
                    # Remove from map so callers get None instead of a dead root
                    self._entries.pop(old_entry.rpc_id, None)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_configs(self) -> list[dict[str, Any]]:
        configs: list[dict[str, Any]] = []
        for path in self._directory.glob("*.json"):
            try:
                with path.open("r", encoding="utf-8") as f:
                    cfg = json.load(f)
                if "id" not in cfg or "port" not in cfg:
                    raise ValueError("Missing 'id' or 'port' key")
                configs.append(cfg)
            except Exception:
                self._logger.exception("Invalid RPC config: %s", path)
        return configs

    def _close_stale(
        self,
        old: dict[str, RpcConnectionEntry],
        new: dict[str, RpcConnectionEntry],
    ) -> None:
        for rpc_id, entry in old.items():
            if rpc_id not in new or new[rpc_id].conn is not entry.conn:
                safe_close(entry.conn)

    async def _close_all(self) -> None:
        async with self._lock:
            entries = self._entries
            self._entries = {}
        for entry in entries.values():
            safe_close(entry.conn)
