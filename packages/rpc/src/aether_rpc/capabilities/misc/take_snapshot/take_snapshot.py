import ida_kernwin
import ida_loader

from ...base import Capability
from ...result import Err, Ok, Result
from ...types import TakeSnapshotResult


class TakeSnapshot(Capability):
    """Takes a snapshot of the current IDA database and saves it to a file.

    Handles the snapshotting of the entire database.
    """

    @property
    def name(self) -> str:
        return "take_snapshot"

    def execute(self) -> Result[TakeSnapshotResult]:
        """Takes database snapshot of the current ida database and saves it to a file.

        Returns:
            A Result whose ``success`` reports whether the snapshot was taken
            and whose ``result`` carries the path to the saved snapshot file.
        """

        snapshot = ida_loader.snapshot_t()
        snapshot.desc = "AETHER snapshot"
        success, err_msg = ida_kernwin.take_database_snapshot(snapshot)

        if success:
            self.logger.info(f"Snapshot saved to {snapshot.filename}")
            return Ok(result=TakeSnapshotResult(snapshot_path=snapshot.filename))

        else:
            self.logger.error(f"Failed to take snapshot: {err_msg}")
            return Err(result=err_msg)
