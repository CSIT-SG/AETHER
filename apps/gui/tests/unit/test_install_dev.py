from __future__ import annotations

import subprocess
from pathlib import Path
from typing import cast

import install_dev as dev
import pytest


class TestDefaultPluginPath:
    def test_uses_appdata_on_windows(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(dev.sys, "platform", "win32")
        monkeypatch.setenv("APPDATA", str(tmp_path))
        assert tmp_path in dev.default_plugin_path().parents

    def test_raises_when_appdata_unset_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dev.sys, "platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)
        with pytest.raises(SystemExit):
            dev.default_plugin_path()

    def test_skips_missing_linux_candidates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dev.sys, "platform", "linux")
        seen: list[Path] = []

        def fake_is_dir(self: Path) -> bool:
            seen.append(self)
            return len(seen) > 1

        monkeypatch.setattr(dev.Path, "is_dir", fake_is_dir)
        assert dev.default_plugin_path() == seen[1]

    def test_raises_when_no_linux_candidate_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dev.sys, "platform", "linux")
        monkeypatch.setattr(dev.Path, "is_dir", lambda self: False)  # noqa: ARG005
        with pytest.raises(SystemExit):
            dev.default_plugin_path()

    def test_raises_on_unsupported_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dev.sys, "platform", "darwin")
        with pytest.raises(SystemExit):
            dev.default_plugin_path()


class TestResolveCommand:
    def test_returns_first_available_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            dev.shutil, "which", lambda name: "found" if name == "python3" else None
        )
        assert dev.resolve_command("python", "python3") == "found"

    def test_raises_when_none_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dev.shutil, "which", lambda name: None)  # noqa: ARG005
        with pytest.raises(SystemExit):
            dev.resolve_command("uv", "uvx")


class TestRun:
    def test_zero_return_code_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            dev.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(command, returncode=0),
        )
        dev.run(["true"])

    def test_nonzero_return_code_raises_system_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            dev.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(command, returncode=7),
        )
        with pytest.raises(SystemExit) as exc_info:
            dev.run(["false"])
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

        dev.remove_path(link)

        assert not link.exists()
        assert real_file.exists()

    def test_removes_file(self, tmp_path: Path) -> None:
        target = tmp_path / "file.py"
        target.write_text("pass")
        dev.remove_path(target)
        assert not target.exists()

    def test_removes_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "pkgdir"
        target.mkdir()
        (target / "inner.py").write_text("pass")
        dev.remove_path(target)
        assert not target.exists()

    def test_noop_for_missing_path(self, tmp_path: Path) -> None:
        dev.remove_path(tmp_path / "missing.py")  # should not raise


class TestInstallRequirements:
    @pytest.mark.parametrize("force_reinstall", [True, False])
    def test_reinstall_flag_follows_request(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, force_reinstall: bool
    ) -> None:
        captured: dict[str, object] = {}
        monkeypatch.setattr(dev, "run", lambda command, cwd=None: captured.update(command=command))  # noqa: ARG005

        dev.install_requirements(
            "uv", tmp_path / "requirements.txt", force_reinstall=force_reinstall
        )

        assert ("--reinstall" in cast(list[str], captured["command"])) is force_reinstall


class TestLinkEntrypoint:
    def test_replaces_existing_entrypoint_with_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink_supported: bool
    ) -> None:
        if not symlink_supported:
            pytest.skip("Symlinks are not available in this environment")
        source = tmp_path / "plugin_dev.py"
        source.write_text("# plugin")
        monkeypatch.setattr(dev, "ENTRYPOINT_SOURCE", source)

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / dev.ENTRYPOINT_NAME).write_text("# stale")

        dev.link_entrypoint(plugin_dir)

        destination = plugin_dir / dev.ENTRYPOINT_NAME
        assert destination.is_symlink()
        assert destination.resolve() == source.resolve()
