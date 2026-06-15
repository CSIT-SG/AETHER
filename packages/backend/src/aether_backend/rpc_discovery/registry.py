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
        configs = self._load_configs()
        if not configs:
            self._logger.warning("No RPC config files found in %s", self._directory)

        live_ids = {cfg["id"] for cfg in configs}

        # Connect only services not already connected
        async with self._lock:
            existing = dict(self._entries)

        tasks = {
            cfg["id"]: connect_with_backoff(cfg["id"], cfg["port"])
            for cfg in configs
            if cfg["id"] not in existing
        }
        results = dict(
            zip(tasks, await asyncio.gather(*tasks.values(), return_exceptions=False), strict=True)
        )

        async with self._lock:
            # Drop entries whose config files are gone
            for rpc_id in list(self._entries):
                if rpc_id not in live_ids:
                    self._logger.info("RPC service %r deregistered (config removed)", rpc_id)
                    safe_close(self._entries.pop(rpc_id).conn)

            # Add newly connected entries
            for rpc_id, entry in results.items():
                if entry is not None:
                    self._entries[rpc_id] = entry

        self._logger.info(
            "RPC registry refreshed: %d services connected %s",
            len(self._entries),
            sorted(self._entries),
        )

    # ------------------------------------------------------------------
    # Heartbeat - ping each live connection, replace dead ones
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._refresh_interval)
                await self._check_connections()
                self._logger.debug("RPC registry heartbeat check complete")
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("RPC registry heartbeat error")

    async def _check_connections(self) -> None:
        async with self._lock:
            snapshot = dict(self._entries)

        live_ids = {cfg["id"] for cfg in self._load_configs()}

        ping_tasks = {
            rpc_id: asyncio.create_task(ping(entry)) for rpc_id, entry in snapshot.items()
        }
        ping_results = await asyncio.gather(*ping_tasks.values(), return_exceptions=True)

        reconnect: list[RpcConnectionEntry] = []
        async with self._lock:
            for rpc_id, ok in zip(ping_tasks, ping_results, strict=True):
                if ok is True:
                    continue
                entry = snapshot[rpc_id]
                safe_close(entry.conn)
                self._entries.pop(rpc_id, None)
                if rpc_id in live_ids:
                    reconnect.append(entry)
                else:
                    self._logger.info("RPC service %r removed (config gone)", rpc_id)

        if not reconnect:
            return

        new_entries = await asyncio.gather(
            *[connect_with_backoff(e.rpc_id, e.port) for e in reconnect],
            return_exceptions=False,
        )
        async with self._lock:
            for entry in filter(None, new_entries):
                self._entries[entry.rpc_id] = entry

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
