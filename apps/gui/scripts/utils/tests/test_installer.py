import re
import sys
import pytest
from pathlib import Path
from unittest.mock import patch

import installer
from installer import format_to_regex, scan, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_globals() -> None:
    """
    installer.py uses module-level mutable lists (IGNORE, REGEXES).
    Reset them before each test so state never leaks between tests.
    """
    installer.IGNORE[:] = [".gitignore", "CONTRIBUTING.md", ".git", "pyrightconfig.json", "uv.lock"]
    installer.REGEXES.clear()


# ---------------------------------------------------------------------------
# format_to_regex
# ---------------------------------------------------------------------------

class TestFormatToRegex:
    def test_returns_compiled_pattern(self):
        result = format_to_regex("*.pyc")
        assert isinstance(result, re.Pattern)

    def test_matches_expected_filename(self):
        pattern = format_to_regex("*.pyc")
        assert pattern.match("foo.pyc")

    def test_does_not_match_unrelated_filename(self):
        pattern = format_to_regex("*.pyc")
        assert not pattern.match("foo.py")

    def test_strips_leading_slash(self):
        # "/build" and "build" should produce equivalent patterns
        with_slash = format_to_regex("/build")
        without_slash = format_to_regex("build")
        assert with_slash.pattern == without_slash.pattern

    def test_strips_trailing_slash(self):
        with_slash = format_to_regex("dist/")
        without_slash = format_to_regex("dist")
        assert with_slash.pattern == without_slash.pattern

    def test_directory_name_pattern(self):
        pattern = format_to_regex("build")
        assert pattern.match("build")

    def test_exact_filename_pattern(self):
        pattern = format_to_regex(".env")
        assert pattern.match(".env")
        assert not pattern.match("production.env")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

class TestScan:
    def setup_method(self):
        _reset_globals()

    def test_returns_false_when_no_regexes(self):
        # REGEXES is empty — nothing should be skipped
        assert scan("anything.py") is False

    def test_returns_true_for_matching_pattern(self):
        installer.REGEXES.append(re.compile(r"ignored_dir"))
        assert scan("ignored_dir") is True

    def test_returns_false_for_non_matching_pattern(self):
        installer.REGEXES.append(re.compile(r"ignored_dir"))
        assert scan("allowed_dir") is False

    def test_returns_true_for_glob_match(self):
        installer.REGEXES.append(format_to_regex("*.pyc"))
        assert scan("module.pyc") is True

    def test_returns_false_for_glob_non_match(self):
        installer.REGEXES.append(format_to_regex("*.pyc"))
        assert scan("module.py") is False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

class TestMain:
    def setup_method(self):
        _reset_globals()

    def test_copies_allowed_file(self, tmp_root: Path, plugin_dir: Path):
        main(str(plugin_dir), str(tmp_root))
        assert (plugin_dir / "main.py").exists()

    def test_copies_allowed_directory(self, tmp_root: Path, plugin_dir: Path):
        main(str(plugin_dir), str(tmp_root))
        assert (plugin_dir / "allowed_dir").is_dir()
        assert (plugin_dir / "allowed_dir" / "helper.py").exists()

    def test_skips_ignored_directory(self, tmp_root: Path, plugin_dir: Path):
        main(str(plugin_dir), str(tmp_root))
        assert not (plugin_dir / "ignored_dir").exists()

    def test_skips_gitignore_file_itself(self, tmp_root: Path, plugin_dir: Path):
        # .gitignore is in the hardcoded IGNORE list
        main(str(plugin_dir), str(tmp_root))
        assert not (plugin_dir / ".gitignore").exists()

    def test_reads_gitignore_patterns(self, tmp_root: Path, plugin_dir: Path):
        # Add an extra pattern to .gitignore and confirm it is honoured
        (tmp_root / ".gitignore").write_text("ignored_dir\nREADME.md\n")
        main(str(plugin_dir), str(tmp_root))
        assert not (plugin_dir / "README.md").exists()

    def test_exits_on_missing_gitignore(self, plugin_dir: Path, tmp_path: Path):
        empty_root = tmp_path / "empty"
        empty_root.mkdir()
        with pytest.raises(SystemExit):
            main(str(plugin_dir), str(empty_root))

    def test_prints_copying_message(self, tmp_root: Path, plugin_dir: Path, capsys):
        main(str(plugin_dir), str(tmp_root))
        captured = capsys.readouterr()
        assert "[INSTALLER] Copying" in captured.out

    def test_prints_skipping_message(self, tmp_root: Path, plugin_dir: Path, capsys):
        main(str(plugin_dir), str(tmp_root))
        captured = capsys.readouterr()
        assert "[INSTALLER] Skipping" in captured.out