from pathlib import Path

from aether_benchmark.utils.task import Task


class StartRPCServerTask(Task[[Path], None]):  # type: ignore[misc]
    async def start(self, ida_dir: Path) -> None:
        # start the RPC server
        pass

    async def cancel(self) -> None:
        # stop the rpc server
        pass
