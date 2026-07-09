from __future__ import annotations

import subprocess
from pathlib import Path

import install_dev as dev
import pytest


class TestDefaultPluginPath:
    def test_uses_appdata_when_set(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        appdata = tmp_path / "AppData" / "Roaming"
        monkeypatch.setenv("APPDATA", str(appdata))
        assert dev.default_plugin_path() == appdata / "Hex-Rays" / "IDA Pro" / "plugins"

    def test_falls_back_to_home_when_appdata_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APPDATA", raising=False)
        assert dev.default_plugin_path() == Path.home() / "Hex-Rays" / "IDA Pro" / "plugins"


class TestResolveCommand:
    def test_returns_first_available_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            dev.shutil, "which", lambda name: "found" if name == "python3" else None
        )
        assert dev.resolve_command("python", "python3") == "found"

    def test_raises_when_none_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dev.shutil, "which", lambda _name: None)
        with pytest.raises(SystemExit):
            dev.resolve_command("uv", "uvx")


class TestRun:
    def test_success_passes_args_through(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        captured: dict[str, object] = {}

        def fake_run(
            command: list[str], cwd: Path | None = None, _text: bool | None = None
        ) -> subprocess.CompletedProcess[str]:
            captured.update(command=command, cwd=cwd)
            return subprocess.CompletedProcess(command, returncode=0)

        monkeypatch.setattr(dev.subprocess, "run", fake_run)
        dev.run(["echo", "hi"], cwd=tmp_path)
        assert captured == {"command": ["echo", "hi"], "cwd": tmp_path}

    def test_nonzero_return_code_raises_system_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            dev.subprocess,
            "run",
            lambda command, _cwd=None, _text=None: subprocess.CompletedProcess(
                command, returncode=7
            ),
        )
        with pytest.raises(SystemExit) as exc_info:
            dev.run(["false"])
        assert exc_info.value.code == 7


class TestEnsurePluginPath:
    def test_creates_nested_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "plugins"
        dev.ensure_plugin_path(target)
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


class TestExportRequirements:
    def test_invokes_uv_export_with_expected_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured_command: list[str] = []
        captured_cwd: Path | None = None

        def fake_run(command: list[str], cwd: Path | None = None) -> None:
            nonlocal captured_command, captured_cwd
            captured_command = command
            captured_cwd = cwd

        monkeypatch.setattr(dev, "run", fake_run)

        result_path = dev.export_requirements("uv")
        try:
            assert captured_command[0] == "uv"
            assert {"export", "--all-packages", "--no-hashes", "--output-file"} <= set(
                captured_command
            )
            assert captured_cwd == dev.ROOT_DIR
        finally:
            result_path.unlink(missing_ok=True)


class TestInstallRequirements:
    def test_invokes_uv_pip_install(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            dev, "run", lambda command, cwd=None: captured.update(command=command, cwd=cwd)
        )

        requirements_path = tmp_path / "requirements.txt"
        dev.install_requirements("uv", requirements_path)

        assert captured["command"] == ["uv", "pip", "install", "-r", str(requirements_path)]
        assert captured["cwd"] == requirements_path.parent


class TestLinkEntrypoint:
    def test_creates_symlink_to_entrypoint_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink_supported: bool
    ) -> None:
        if not symlink_supported:
            pytest.skip("Symlinks are not available in this environment")
        fake_source = tmp_path / "plugin-dev.py"
        fake_source.write_text("# plugin")
        monkeypatch.setattr(dev, "ENTRYPOINT_SOURCE", fake_source)

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        dev.link_entrypoint(plugin_dir)

        destination = plugin_dir / dev.ENTRYPOINT_NAME
        assert destination.is_symlink()
        assert destination.resolve() == fake_source.resolve()

    def test_replaces_existing_entrypoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink_supported: bool
    ) -> None:
        if not symlink_supported:
            pytest.skip("Symlinks are not available in this environment")
        fake_source = tmp_path / "plugin-dev.py"
        fake_source.write_text("# plugin v2")
        monkeypatch.setattr(dev, "ENTRYPOINT_SOURCE", fake_source)

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / dev.ENTRYPOINT_NAME).write_text("# stale")

        dev.link_entrypoint(plugin_dir)

        destination = plugin_dir / dev.ENTRYPOINT_NAME
        assert destination.is_symlink()
        assert destination.resolve() == fake_source.resolve()
