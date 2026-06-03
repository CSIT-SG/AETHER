import re
import sys
from pathlib import Path

import pytest

PARENT_DIR = Path(__file__).parent.parent
sys.path.append(str(PARENT_DIR))

import installer
from installer import format_to_regex, main, scan, REGEXES, IGNORE


def _reset_globals() -> None:
    """
    installer.py uses module-level mutable lists (IGNORE, REGEXES).
    Reset them before each test so state never leaks between tests.
    """
    IGNORE[:] = [".gitignore", "CONTRIBUTING.md", ".git", "pyrightconfig.json", "uv.lock"]
    REGEXES.clear()


class TestFormatToRegex:
    def test_returns_compiled_pattern(self) -> None:
        result = format_to_regex("*.pyc")
        assert isinstance(result, re.Pattern)

    def test_matches_expected_filename(self) -> None:
        pattern = format_to_regex("*.pyc")
        assert pattern.match("foo.pyc")

    def test_does_not_match_unrelated_filename(self) -> None:
        pattern = format_to_regex("*.pyc")
        assert not pattern.match("foo.py")

    def test_strips_leading_slash(self) -> None:
        # "/build" and "build" should produce equivalent patterns
        with_slash = format_to_regex("/build")
        without_slash = format_to_regex("build")
        assert with_slash.pattern == without_slash.pattern

    def test_strips_trailing_slash(self) -> None:
        with_slash = format_to_regex("dist/")
        without_slash = format_to_regex("dist")
        assert with_slash.pattern == without_slash.pattern

    def test_directory_name_pattern(self) -> None:
        pattern = format_to_regex("build")
        assert pattern.match("build")

    def test_exact_filename_pattern(self) -> None:
        pattern = format_to_regex(".env")
        assert pattern.match(".env")
        assert not pattern.match("production.env")


class TestScan:
    def setup_method(self) -> None:
        _reset_globals()

    def test_returns_false_when_no_regexes(self) -> None:
        # REGEXES is empty — nothing should be skipped
        assert scan("anything.py") is False

    def test_returns_true_for_matching_pattern(self) -> None:
        REGEXES.append(re.compile(r"ignored_dir"))
        assert scan("ignored_dir") is True

    def test_returns_false_for_non_matching_pattern(self) -> None:
        REGEXES.append(re.compile(r"ignored_dir"))
        assert scan("allowed_dir") is False

    def test_returns_true_for_glob_match(self) -> None:
        REGEXES.append(format_to_regex("*.pyc"))
        assert scan("module.pyc") is True

    def test_returns_false_for_glob_non_match(self) -> None:
        REGEXES.append(format_to_regex("*.pyc"))
        assert scan("module.py") is False


class TestMain:
    def setup_method(self) -> None:
        _reset_globals()

    def test_copies_allowed_file(self, tmp_root: Path, plugin_dir: Path) -> None:
        main(str(plugin_dir), str(tmp_root))
        assert (plugin_dir / "main.py").exists()

    def test_copies_allowed_directory(self, tmp_root: Path, plugin_dir: Path) -> None:
        main(str(plugin_dir), str(tmp_root))
        assert (plugin_dir / "allowed_dir").is_dir()
        assert (plugin_dir / "allowed_dir" / "helper.py").exists()

    def test_skips_ignored_directory(self, tmp_root: Path, plugin_dir: Path) -> None:
        main(str(plugin_dir), str(tmp_root))
        assert not (plugin_dir / "ignored_dir").exists()

    def test_skips_gitignore_file_itself(self, tmp_root: Path, plugin_dir: Path) -> None:
        # .gitignore is in the hardcoded IGNORE list
        main(str(plugin_dir), str(tmp_root))
        assert not (plugin_dir / ".gitignore").exists()

    def test_reads_gitignore_patterns(self, tmp_root: Path, plugin_dir: Path) -> None:
        # Add an extra pattern to .gitignore and confirm it is honoured
        (tmp_root / ".gitignore").write_text("ignored_dir\nREADME.md\n")
        main(str(plugin_dir), str(tmp_root))
        assert not (plugin_dir / "README.md").exists()
