from __future__ import annotations

import subprocess
from pathlib import Path
from typing import cast

import install_prod as prod
import pytest


class TestDefaultPluginPath:
    def test_uses_appdata_on_windows(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(prod.sys, "platform", "win32")
        monkeypatch.setenv("APPDATA", str(tmp_path))
        assert tmp_path in prod.default_plugin_path().parents

    def test_raises_when_appdata_unset_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(prod.sys, "platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)
        with pytest.raises(SystemExit):
            prod.default_plugin_path()

    def test_skips_missing_linux_candidates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(prod.sys, "platform", "linux")
        seen: list[Path] = []

        def fake_is_dir(self: Path) -> bool:
            seen.append(self)
            return len(seen) > 1

        monkeypatch.setattr(prod.Path, "is_dir", fake_is_dir)
        assert prod.default_plugin_path() == seen[1]

    def test_raises_when_no_linux_candidate_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(prod.sys, "platform", "linux")
        monkeypatch.setattr(prod.Path, "is_dir", lambda self: False)  # noqa: ARG005
        with pytest.raises(SystemExit):
            prod.default_plugin_path()

    def test_raises_on_unsupported_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(prod.sys, "platform", "darwin")
        with pytest.raises(SystemExit):
            prod.default_plugin_path()


class TestResolveCommand:
    def test_returns_first_available_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            prod.shutil, "which", lambda name: "found" if name == "python3" else None
        )
        assert prod.resolve_command("python", "python3") == "found"

    def test_raises_when_none_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(prod.shutil, "which", lambda name: None)  # noqa: ARG005
        with pytest.raises(SystemExit):
            prod.resolve_command("python", "python3")


class TestRun:
    def test_zero_return_code_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            prod.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(command, returncode=0),
        )
        prod.run(["true"])

    def test_nonzero_return_code_raises_system_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            prod.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(command, returncode=7),
        )
        with pytest.raises(SystemExit) as exc_info:
            prod.run(["false"])
        assert exc_info.value.code == 7


class TestRemovePath:
    def test_removes_symlink_without_touching_target(
        self, tmp_path: Path, symlink_supported: bool
    ) -> None:
        if not symlink_supported:
            pytest.skip("Symlinks are not available in this environment")
        real_file = tmp_path / "real.py"
        real_file.write_text("pass")
        link = tmp_path / "link.py"
        link.symlink_to(real_file)

        prod.remove_path(link)

        assert not link.exists()
        assert real_file.exists()

    def test_removes_file(self, tmp_path: Path) -> None:
        target = tmp_path / "file.py"
        target.write_text("pass")
        prod.remove_path(target)
        assert not target.exists()

    def test_removes_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "pkgdir"
        target.mkdir()
        (target / "inner.py").write_text("pass")
        prod.remove_path(target)
        assert not target.exists()

    def test_noop_for_missing_path(self, tmp_path: Path) -> None:
        prod.remove_path(tmp_path / "missing.py")  # should not raise


class TestResourceDir:
    def test_returns_source_dir_when_bundle_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "wheels").mkdir()
        monkeypatch.setattr(prod, "SOURCE_DIR", tmp_path)

        assert prod.resource_dir() == tmp_path

    def test_raises_when_bundle_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "requirements.txt").write_text("")
        monkeypatch.setattr(prod, "SOURCE_DIR", tmp_path)

        with pytest.raises(SystemExit):
            prod.resource_dir()


class TestInstallRequirements:
    @pytest.mark.parametrize("force_reinstall", [True, False])
    def test_reinstall_flag_follows_request(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, force_reinstall: bool
    ) -> None:
        captured: dict[str, object] = {}
        monkeypatch.setattr(prod, "run", lambda command, cwd=None: captured.update(command=command))  # noqa: ARG005

        prod.install_requirements(bundle_dir=tmp_path, force_reinstall=force_reinstall)

        assert ("--force-reinstall" in cast(list[str], captured["command"])) is force_reinstall


class TestCopyEntrypoint:
    def test_replaces_existing_entrypoint_with_a_copy(self, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "plugin.py").write_text("# new content")

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / prod.ENTRYPOINT_NAME).write_text("# old content")

        prod.copy_entrypoint(plugin_dir, bundle_dir)

        destination = plugin_dir / prod.ENTRYPOINT_NAME
        assert not destination.is_symlink()
        assert destination.read_text() == "# new content"

    def test_raises_when_source_plugin_missing(self, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        with pytest.raises(SystemExit):
            prod.copy_entrypoint(plugin_dir, bundle_dir)
