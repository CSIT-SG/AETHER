from os.path import islink
from pathlib import Path

import pytest
import sys

PARENT_DIR = Path(__file__).parent.parent
sys.path.append(str(PARENT_DIR))

from linker import LINKS, cleanup, create_link, main


class TestCleanup:
    def test_removes_existing_symlink(self, dst_dir: Path, src_dir: Path) -> None:
        link = dst_dir / "existing.py"
        link.symlink_to(src_dir / "plugin.py")
        assert link.is_symlink()

        cleanup(str(link))

        assert not link.exists()

    def test_does_nothing_when_no_link_exists(self, dst_dir: Path) -> None:
        path = str(dst_dir / "nonexistent.py")
        cleanup(path)

    def test_does_not_remove_real_file(self, dst_dir: Path) -> None:
        real_file = dst_dir / "real.py"
        real_file.write_text("# real")
        cleanup(str(real_file))
        assert real_file.exists()


class TestCreateLink:
    def test_creates_symlink(self, src_dir: Path, dst_dir: Path) -> None:
        src = str(src_dir / "plugin.py")
        dst = str(dst_dir / "aether-next-gui.py")

        create_link(src, dst)

        assert islink(dst)

    def test_symlink_points_to_correct_source(self, src_dir: Path, dst_dir: Path) -> None:
        src = str(src_dir / "plugin.py")
        dst = str(dst_dir / "aether-next-gui.py")

        create_link(src, dst)

        assert Path(dst).resolve() == Path(src).resolve()

    def test_prints_created_message(
        self, src_dir: Path, dst_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = str(src_dir / "plugin.py")
        dst = str(dst_dir / "aether-next-gui.py")
        create_link(src, dst)
        captured = capsys.readouterr()
        assert "Created Link" in captured.out

    def test_prints_already_exists_message_when_link_exists(
        self, src_dir: Path, dst_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = str(src_dir / "plugin.py")
        dst = str(dst_dir / "aether-next-gui.py")
        Path(dst).symlink_to(src)  # pre-create the link
        create_link(src, dst)  # should not raise, should print message
        captured = capsys.readouterr()
        assert "already exists" in captured.out

    def test_exits_on_unexpected_error(
        self, dst_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        Pass a source path whose parent directory does not exist to
        Force an OSError inside create_link
        """
        src = "/nonexistent/path/plugin.py"
        dst = str(dst_dir / "bad.py")

        create_link(src, dst)
        captured = capsys.readouterr()
        assert "Invalid Source" in captured.out


class TestMain:
    def test_creates_all_links(self, src_dir: Path, dst_dir: Path) -> None:
        main(str(src_dir), str(dst_dir))
        for dst_name in LINKS.values():
            dst = dst_dir / dst_name
            assert islink(str(dst)), f"Expected symlink not found: {dst}"

    def test_each_link_points_to_correct_source(self, src_dir: Path, dst_dir: Path) -> None:
        main(str(src_dir), str(dst_dir))
        for src_name, dst_name in LINKS.items():
            src = src_dir / src_name
            dst = dst_dir / dst_name
            assert dst.resolve() == src.resolve()

    def test_replaces_stale_link(self, src_dir: Path, dst_dir: Path) -> None:
        # Pre-create a stale link pointing at a nonexistent path
        stale_target = src_dir / "plugin.py"
        dst = dst_dir / "aether-next-gui.py"
        dst.symlink_to("/stale/path/plugin.py")
        assert islink(str(dst))

        main(str(src_dir), str(dst_dir))

        # Link should now resolve to the correct source
        assert dst.resolve() == stale_target.resolve()

    def test_prints_output_for_each_link(
        self, src_dir: Path, dst_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(str(src_dir), str(dst_dir))
        captured = capsys.readouterr()
        assert captured.out.count("Created Link") == len(LINKS)
