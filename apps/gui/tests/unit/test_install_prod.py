from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import install_prod as prod
import pytest


class TestDefaultPluginPath:
    def test_uses_appdata_when_set(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        appdata = tmp_path / "AppData" / "Roaming"
        monkeypatch.setenv("APPDATA", str(appdata))
        assert prod.default_plugin_path() == appdata / "Hex-Rays" / "IDA Pro" / "plugins"

    def test_falls_back_to_home_when_appdata_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APPDATA", raising=False)
        assert prod.default_plugin_path() == Path.home() / "Hex-Rays" / "IDA Pro" / "plugins"


class TestResolveCommand:
    def test_returns_first_available_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            prod.shutil, "which", lambda name: "found" if name == "python3" else None
        )
        assert prod.resolve_command("python", "python3") == "found"


class TestRun:
    def test_success_passes_args_through(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        captured: dict[str, object] = {}

        def fake_run(
            command: list[str],
            cwd: Path | None = None,
            text: bool | None = None,  # noqa: ARG001
        ) -> subprocess.CompletedProcess[str]:
            captured.update(command=command, cwd=cwd)
            return subprocess.CompletedProcess(command, returncode=0)

        monkeypatch.setattr(prod.subprocess, "run", fake_run)
        prod.run(["echo", "hi"], cwd=tmp_path)
        assert captured == {"command": ["echo", "hi"], "cwd": tmp_path}

    def test_nonzero_return_code_raises_system_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            prod.subprocess,
            "run",
            lambda command, cwd=None, text=None: subprocess.CompletedProcess(command, returncode=7),  # noqa: ARG005
        )
        with pytest.raises(SystemExit) as exc_info:
            prod.run(["false"])
        assert exc_info.value.code == 7


class TestEnsurePluginPath:
    def test_creates_nested_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "plugins"
        prod.ensure_plugin_path(target)
        assert target.is_dir()


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
    def test_prefers_source_dir_when_bundle_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "requirements.txt").write_text("")
        (source_dir / "wheels").mkdir()

        monkeypatch.setattr(prod, "SOURCE_DIR", source_dir)
        monkeypatch.setattr(prod, "DIST_DIR", tmp_path / "unused_dist")

        assert prod.resource_dir() == source_dir

    def test_falls_back_to_dist_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        (dist_dir / "requirements.txt").write_text("")
        (dist_dir / "wheels").mkdir()

        monkeypatch.setattr(prod, "SOURCE_DIR", tmp_path / "empty_source")
        monkeypatch.setattr(prod, "DIST_DIR", dist_dir)

        assert prod.resource_dir() == dist_dir

    def test_raises_when_bundle_incomplete_or_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "requirements.txt").write_text("")

        monkeypatch.setattr(prod, "SOURCE_DIR", source_dir)
        monkeypatch.setattr(prod, "DIST_DIR", tmp_path / "empty_dist")

        with pytest.raises(SystemExit):
            prod.resource_dir()


class TestInstallRequirements:
    def test_invokes_pip_install_user(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            prod, "run", lambda command, cwd=None: captured.update(command=command, cwd=cwd)
        )

        bundle_dir = tmp_path / "bundle"
        prod.install_requirements(bundle_dir)

        assert captured["command"] == [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--user",
            "-r",
            str(bundle_dir / "requirements.txt"),
        ]
        assert captured["cwd"] == bundle_dir


class TestCopyEntrypoint:
    def test_copies_plugin_py_to_destination(self, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "plugin.py").write_text("# prod plugin")

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        prod.copy_entrypoint(plugin_dir, bundle_dir)

        destination = plugin_dir / prod.ENTRYPOINT_NAME
        assert not destination.is_symlink()
        assert destination.read_text() == "# prod plugin"

    def test_raises_when_source_plugin_missing(self, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        with pytest.raises(SystemExit):
            prod.copy_entrypoint(plugin_dir, bundle_dir)

    def test_replaces_existing_destination_file(self, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "plugin.py").write_text("# new content")

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / prod.ENTRYPOINT_NAME).write_text("# old content")

        prod.copy_entrypoint(plugin_dir, bundle_dir)

        assert (plugin_dir / prod.ENTRYPOINT_NAME).read_text() == "# new content"
