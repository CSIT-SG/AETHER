import os
import queue
import sys
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any, cast

import idapro

from .base import IDAExecutor

_SENTINEL = object()


def configure_idapro(ida_install_dir: str) -> None:
    os.environ.setdefault("IDADIR", ida_install_dir)
    if ida_install_dir not in sys.path:
        sys.path.insert(0, ida_install_dir)


class HeadlessExecutor(IDAExecutor):
    def __init__(
        self,
        idb_path: str,
        ida_install_dir: str,
    ) -> None:
        self._idb_path = idb_path
        self._ida_install_dir = ida_install_dir
        self._db_open = False
        self._work_queue: queue.Queue[
            tuple[Callable[..., Any], dict[str, Any], Future[Any]] | object
        ] = queue.Queue()

    def execute(
        self,
        callback: Callable[..., Any],
        arguments: dict[str, Any],
    ) -> Any:
        if not self._db_open:
            raise RuntimeError("Database not open")

        future: Future[Any] = Future()
        self._work_queue.put((callback, arguments, future))
        return future.result()  # blocks the RPC worker thread until done

    def pump(self) -> None:
        while True:
            try:
                item = self._work_queue.get(timeout=0.5)
            except queue.Empty:
                continue  # re-check, allows KeyboardInterrupt to be delivered
            if item is _SENTINEL:
                break
            callback, arguments, future = cast(
                tuple[Callable[..., Any], dict[str, Any], Future[Any]], item
            )
            try:
                future.set_result(callback(**arguments))
            except BaseException as exc:
                future.set_exception(exc)

        if self._db_open:
            idapro.close_database()
            self._db_open = False

    def startup(self) -> None:
        configure_idapro(self._ida_install_dir)
        result = idapro.open_database(
            self._idb_path,
            run_auto_analysis=True,
        )
        if result != 0:
            raise RuntimeError(f"Failed to open database: {result}")
        self._db_open = True

    def shutdown(self) -> None:
        self._work_queue.put(_SENTINEL)  # unblocks pump()
