import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Any, NamedTuple

from aether_rpc.registry import RPCFileRegistry
from aether_utils.data_dir import get_data_dir
from aether_utils.logger import get_logger
from watchfiles import Change, awatch

from .connection import RpcConnectionEntry, connect_with_backoff, ping, safe_close
from .constants import DISCOVERY_REFRESH_INTERVAL, RPC_REGISTRY_KEY


class _RpcFileConfigEntry(NamedTuple):
    port: int
    path: Path


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
        self._logger = get_logger(RPC_REGISTRY_KEY)

    # Lifecycle

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name=f"{RPC_REGISTRY_KEY}-heartbeat",
        )
        self._file_watching_task = asyncio.create_task(
            self._listen(),
            name=f"{RPC_REGISTRY_KEY}-file-watcher",
        )

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False

        for task in filter(None, (self._heartbeat_task, self._file_watching_task)):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        self._heartbeat_task = None
        self._file_watching_task = None

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
            return sorted(self._entries.keys())

    async def all(self) -> dict[str, Any]:
        async with self._lock:
            return {k: v.root for k, v in self._entries.items()}

    # Heartbeat
    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                configs = self._load_configs()  # {rpc_id: _RpcFileConfigEntry}
                async with self._lock:
                    snapshot = dict(self._entries)  # copy

                results = await asyncio.gather(
                    *(ping(e) for e in snapshot.values()), return_exceptions=True
                )
                dead_ids = {
                    rid for rid, ok in zip(snapshot, results, strict=True) if ok is not True
                }
                new_ids = set(configs) - set(snapshot)

                # calculate the paths to reconnect to: dead paths union new paths
                reconnect_paths = {rid: snapshot[rid].path for rid in dead_ids} | {
                    rid: configs[rid].path for rid in new_ids
                }

                results = await asyncio.gather(
                    *(self._check_config_live(p) for p in reconnect_paths.values()),
                    return_exceptions=True,
                )
                for rid, r in zip(reconnect_paths, results, strict=True):
                    if isinstance(r, Exception):
                        self._logger.exception("Failed to reconnect %r", rid, exc_info=r)

                self._logger.info("heartbeat complete; active: %s", sorted(self._entries) or "none")
                await asyncio.sleep(self._refresh_interval)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._logger.exception("RPC registry heartbeat error")

    # Watcher
    async def _listen(self) -> None:
        async for changes in awatch(self._directory):
            for change_type, change_path in changes:
                path = Path(change_path)

                if path.suffix != ".json":
                    continue

                if change_type not in (Change.added, Change.deleted):
                    continue

                try:
                    self._logger.info(
                        "RPC registry watcher detected %s config: %r",
                        change_type.name,
                        change_path,
                    )
                    await self._check_config_live(path)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._logger.exception(
                        "RPC registry watcher error handling %r",
                        change_path,
                    )

    # Internal helpers

    def _load_configs(self) -> dict[str, _RpcFileConfigEntry]:
        """Returns {rpc_id: _RpcFileConfigEntry} for all .json files in the registry directory"""
        return {
            entry.id: _RpcFileConfigEntry(entry.port, path)
            for path in self._directory.glob("*.json")
            if (entry := RPCFileRegistry.load(path))
        }

    async def _check_config_live(self, path: Path) -> bool:
        """Connects/reconnects to the service described by `path` and
        updates the registry. Returns True if live."""
        entry = RPCFileRegistry.load(path)

        # file is gone, find any entry we previously
        # associated with this path and tear it down
        if entry is None:
            async with self._lock:
                old = None
                for rid, existing in self._entries.items():
                    if existing.path == path:
                        old = self._entries.pop(rid)
                        break
            if old:
                safe_close(old.conn)
            return False

        exists = await connect_with_backoff(rpc_id=entry.id, port=entry.port, path=path)
        async with self._lock:
            old = self._entries.get(entry.id)
            if exists:
                self._entries[entry.id] = exists
            else:
                self._entries.pop(entry.id, None)
                path.unlink(missing_ok=True)
            if old is not None and old is not exists:
                safe_close(old.conn)
        return bool(exists)

    async def _close_all(self) -> None:
        async with self._lock:
            entries = self._entries
            self._entries = {}
        for entry in entries.values():
            safe_close(entry.conn)
