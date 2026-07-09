# type: ignore
from collections.abc import Callable
from pathlib import Path

import pytest
import rpyc


@pytest.mark.dependency(scope="package")
class TestTakeSnapshot:
    """Verifies that take_snapshot writes a snapshot file into the binary's directory."""

    def test_snapshot_is_created_on_disk(
        self, ida_client: rpyc.Connection, get_binary: Callable[..., Path], BIN_NAME: str
    ) -> None:
        bin_dir = get_binary(BIN_NAME).parent

        result = ida_client.root.take_snapshot()
        assert result.success is True

        snapshot_path = Path(str(result.result["snapshot_path"]))
        assert str(snapshot_path) != ""

        # The snapshot file itself must exist on disk...
        assert snapshot_path.exists()
        assert snapshot_path.is_file()

        # ...and it must live in the same directory as the analyzed binary.
        assert snapshot_path.parent == bin_dir

    def test_snapshot_appears_in_binary_directory_listing(
        self, ida_client: rpyc.Connection, get_binary: Callable[..., Path], BIN_NAME: str
    ) -> None:
        bin_dir = get_binary(BIN_NAME).parent

        before = set(bin_dir.iterdir())
        result = ida_client.root.take_snapshot()
        assert result.success is True

        after = set(bin_dir.iterdir())
        new_files = after - before

        # Taking a snapshot should have produced at least one new file in the
        # binary's directory, and the returned path should be among them.
        snapshot_path = Path(str(result.result["snapshot_path"])).resolve()
        assert snapshot_path in {p.resolve() for p in after}
        assert new_files, "expected take_snapshot to create a new file in the binary directory"
