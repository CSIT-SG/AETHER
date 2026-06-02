# rpc/executors/headless.py
import os
import sys
import idapro
from typing import Any, Callable
from .base import IDAExecutor


def configure_idapro(ida_install_dir: str) -> None:
    """
    Must be called before importing any ida_* modules or opening a database.

    Sets up the IDA root so idapro can find its shared libraries and license.
    Calling this more than once is safe — it's idempotent.
    """
    # idapro uses this env var to locate IDA's shared libs (ida.dll / libida.so)
    # read: https://pypi.org/project/idapro/ under advanced usage for details
    os.environ.setdefault("IDADIR", ida_install_dir)

    # Also needs to be on sys.path so ida_* modules (ida_funcs, idc, etc.) are importable
    if ida_install_dir not in sys.path:
        sys.path.insert(0, ida_install_dir)

    # CLANKER output: needs to be verified.
    # idapro itself looks for the license via IDAUSR or the standard IDA license path.
    # If the license is non-standard, set this too:
    #   os.environ.setdefault("IDAUSR", "/path/to/license/dir")


class HeadlessExecutor(IDAExecutor):
    def __init__(self, idb_path: str, ida_install_dir: str) -> None:
        self._idb_path = idb_path
        self._ida_install_dir = ida_install_dir
        self._db_open = False

    async def execute(self, callback: Callable[..., Any], arguments: dict[str, Any]) -> Any:
        if not self._db_open:
            raise RuntimeError("Database not open — startup() was not called")
        return callback(**arguments)

    async def startup(self) -> None:
        configure_idapro(self._ida_install_dir)
        idapro.open_database(self._idb_path, run_auto_analysis=True)
        self._db_open = True

    async def shutdown(self) -> None:
        if self._db_open:
            idapro.close_database()
            self._db_open = False
