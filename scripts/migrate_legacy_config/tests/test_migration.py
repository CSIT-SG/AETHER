import importlib
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT_DIR = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT_DIR))

from scripts.migrate_legacy_config.candidates import choose_candidate  # noqa: E402
from scripts.migrate_legacy_config.schema import ConfigCandidate  # noqa: E402
from scripts.migrate_legacy_config.storage import (  # noqa: E402
    backup_existing_config,
    read_json,
    write_json,
)


def _candidate(source: str, digest: str, modified: datetime) -> ConfigCandidate:
    return ConfigCandidate(
        source=source,
        path=Path(f"{source}.json"),
        config={"provider": {"models": {}}},
        digest=digest,
        modified=modified,
        migrated_keys=(),
        dropped_keys=(),
        unmapped_keys=(),
    )


def test_flat_aether_ida_config_migrates_without_paths_module() -> None:
    sys.modules.pop("scripts.migrate_legacy_config.paths", None)
    migration = importlib.import_module("scripts.migrate_legacy_config.migration")

    assert "scripts.migrate_legacy_config.paths" not in sys.modules

    legacy_config = {
        "OPENAI_API_KEY": "",
        "OPENAI_MODEL": "qwen/qwen3-coder",
        "OPENAI_BASE_URL": "https://openrouter.ai/api/v1",
        "MCP_SERVER_URL": "http://127.0.0.1:8744/sse",
        "MAX_ITERATIONS": 5,
        "GATHERER_MODEL": "qwen/qwen3.5-397b-a17b",
        "ANNOTATOR_MODEL": "qwen/qwen3-next-80b-a3b-instruct",
        "AI_DECOMP_MODEL": "qwen/qwen3-next-80b-a3b-instruct",
        "SINGLE_ANALYSIS_MODEL": "qwen/qwen3-next-80b-a3b-instruct",
        "STRUCT_CREATOR_MODEL": "qwen/qwen3-next-80b-a3b-instruct",
        "INDEX_AGENT_MODEL": "qwen/qwen3-next-80b-a3b-instruct",
        "INDEXING_MODEL": "qwen/qwen3-next-80b-a3b-instruct",
        "INDEXING_BATCH_SIZE": 50,
        "INDEXING_DECOMP_CHUNK_SIZE": 20,
        "INDEXING_MAX_FUNC_SIZE_BYTES": 24576,
        "INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES": 12288,
        "INDEXING_DECOMP_HEARTBEAT_INTERVAL_S": 5.0,
        "INDEXING_STUCK_FUNCTION_THRESHOLD_S": 45,
        "INDEXING_SLOW_DECOMP_THRESHOLD_S": 5,
        "INDEXING_DEBUG_LOGS": True,
        "INDEXING_FAILED_RETRY_MAX": 5,
        "INDEXING_PSEUDOCODE_CACHE_ENABLED": True,
        "INDEXING_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC": 0,
        "INDEXING_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS": 0,
        "INDEXING_MAX_TOKENS": 8000,
        "ANALYSIS_MAX_TOKENS": 8000,
        "SYSTEM_PROMPT_AT_BOTTOM": False,
        "PROMPT_TOKEN_WARNING": 24000,
        "ANNOTATOR_MAX_TOKENS": 8000,
        "DEOBFUSCATOR_MAX_TOKENS": 8000,
        "CHATBOT_MAX_TOKENS": 8000,
        "CHATBOT_IDX_DIALOG": False,
        "OPENAI_EXTRA_BODY": {},
        "CUSTOM_CA_CERT_PATH": "",
        "CLIENT_CERT_PATH": "",
        "CLIENT_KEY_PATH": "",
        "DEBUG": False,
        "ALWAYS_PROMPT_MODEL": True,
        "MODEL_LIST": {
            "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
            "Qwen: Qwen3.5": "qwen/qwen3.5-397b-a17b",
            "OpenAI": "openai/gpt-5.5",
            "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct",
            "Minimax": "minimax/minimax-m2.7",
        },
        "USE_DESC": True,
        "USE_COMMENTS": True,
        "RENAME_VARS": True,
        "RENAME_FUNCS": True,
        "RENAME_FILTER_ENABLED": True,
        "COMMENT_EVERY_LINE": True,
        "UNFLATTEN_ATTEMPTS": 3,
    }

    expected_config = {
        "provider": {
            "gateway_url": "https://openrouter.ai/api/v1",
            "api_key": "",
            "models": {
                "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
                "Qwen: Qwen3.5": "qwen/qwen3.5-397b-a17b",
                "OpenAI": "openai/gpt-5.5",
                "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct",
                "Minimax": "minimax/minimax-m2.7",
            },
            "default_model": "Qwen: Qwen3 Coder 480B A35B",
            "extra_body": {},
        },
        "subagents": {
            "gatherer_model": "Qwen: Qwen3.5",
            "annotator_model": "Qwen: Qwen3 Next 80B A3B Instruct",
            "single_analysis_model": "Qwen: Qwen3 Next 80B A3B Instruct",
            "struct_creator_model": "Qwen: Qwen3 Next 80B A3B Instruct",
            "index_agent_model": "Qwen: Qwen3 Next 80B A3B Instruct",
        },
        "features": None,
        "debug": False,
        "backup": True,
        "experimental": None,
        "tls": {"client_cert_path": None, "client_key_path": None},
    }

    result = migration.normalize_legacy_config(legacy_config)

    assert result.config == expected_config
    assert result.unmapped_keys == ()
    # Every legacy key is either migrated or knowingly dropped.
    assert set(result.migrated_keys) | set(result.dropped_keys) == set(legacy_config)
    assert "MCP_SERVER_URL" in result.dropped_keys
    assert "OPENAI_MODEL" in result.migrated_keys


def test_choose_candidate_refuses_when_configs_differ() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0)
    candidates = [
        _candidate("AETHER-IDA", "digest-a", now),
        _candidate("AETHER", "digest-b", now + timedelta(hours=1)),
    ]

    assert choose_candidate(candidates) is None


def test_choose_candidate_picks_most_recent_when_configs_match() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0)
    older = _candidate("AETHER-IDA", "same-digest", now)
    newer = _candidate("AETHER", "same-digest", now + timedelta(hours=1))

    assert choose_candidate([older, newer]) is newer
    assert choose_candidate([newer, older]) is newer


def test_choose_candidate_returns_none_when_empty() -> None:
    assert choose_candidate([]) is None


def test_backup_existing_config_copies_before_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "config.json"
    write_json(destination, {"provider": {"models": {}}, "debug": False})

    backup_path = backup_existing_config(destination)

    assert backup_path is not None
    assert backup_path.exists()
    assert read_json(backup_path) == read_json(destination)

    write_json(destination, {"provider": {"models": {}}, "debug": True})
    # The backup still holds the pre-overwrite content.
    assert read_json(backup_path)["debug"] is False


def test_backup_existing_config_noop_when_absent(tmp_path: Path) -> None:
    assert backup_existing_config(tmp_path / "missing.json") is None


def test_print_migrated_keys_lists_transferred(capsys) -> None:
    from scripts.migrate_legacy_config.cli import print_migrated_keys

    candidate = ConfigCandidate(
        source="AETHER-IDA",
        path=Path("legacy.json"),
        config={},
        digest="d",
        modified=datetime(2026, 1, 1),
        migrated_keys=("OPENAI_MODEL", "DEBUG"),
        dropped_keys=(),
        unmapped_keys=(),
    )

    print_migrated_keys(candidate)
    out = capsys.readouterr().out
    assert "Migrated 2 legacy keys:" in out
    # Each transferred key is shown mapped to its destination path.
    assert "OPENAI_MODEL -> provider.default_model" in out
    assert "DEBUG        -> debug" in out


def test_print_migrated_keys_handles_none(capsys) -> None:
    from scripts.migrate_legacy_config.cli import print_migrated_keys

    print_migrated_keys(_candidate("AETHER-IDA", "d", datetime(2026, 1, 1)))
    assert "Migrated 0 legacy keys: (none)" in capsys.readouterr().out


def test_write_migration_report_writes_json(tmp_path: Path) -> None:
    from scripts.migrate_legacy_config.cli import write_migration_report

    candidate = ConfigCandidate(
        source="AETHER-IDA",
        path=Path("legacy.json"),
        config={"provider": {"models": {}}},
        digest="d",
        modified=datetime(2026, 1, 1),
        migrated_keys=("OPENAI_MODEL",),
        dropped_keys=("MCP_SERVER_URL",),
        unmapped_keys=("SOME_UNKNOWN_KEY",),
    )
    report_path = tmp_path / "report.json"

    assert write_migration_report(report_path, candidate, tmp_path / "dest.json") is True

    written = read_json(report_path)
    assert written["migrated_keys"] == ["OPENAI_MODEL"]
    assert "MCP_SERVER_URL" in written["dropped"]
    assert written["unmapped_keys"] == ["SOME_UNKNOWN_KEY"]


def test_write_migration_report_fails_gracefully_on_bad_path(tmp_path: Path) -> None:
    from scripts.migrate_legacy_config.cli import write_migration_report

    candidate = _candidate("AETHER-IDA", "d", datetime(2026, 1, 1))
    # A directory can't be opened for writing; the report must fail, not raise.
    unwritable = tmp_path / "a_directory"
    unwritable.mkdir()

    assert write_migration_report(unwritable, candidate, tmp_path / "dest.json") is False


def test_report_flag_defaults_to_package_directory() -> None:
    from scripts.migrate_legacy_config.cli import DEFAULT_REPORT_PATH, PACKAGE_DIR, parse_args

    argv = sys.argv
    sys.argv = ["prog", "--source-path", "x.json", "--report"]
    try:
        args = parse_args()
    finally:
        sys.argv = argv

    # --report with no value resolves to a fixed path in the tool's own directory,
    # independent of the caller's working directory.
    assert args.report == DEFAULT_REPORT_PATH
    assert args.report.parent == PACKAGE_DIR
    assert args.report.is_absolute()
