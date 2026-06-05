import os
import sys
from collections.abc import Callable
from typing import Any

import idapro

from .base import IDAExecutor


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

    def execute(
        self,
        callback: Callable[..., Any],
        arguments: dict[str, Any],
    ) -> Any:
        if not self._db_open:
            raise RuntimeError("Database not open")

        return callback(**arguments)

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
        if self._db_open:
            idapro.close_database()
            self._db_open = False
