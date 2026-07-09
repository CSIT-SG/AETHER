import argparse
import sys
from pathlib import Path
from typing import Any

from .candidates import choose_candidate, discover_candidates
from .mapping import DROPPED_FIELD_NOTES, FIELD_MAPPINGS
from .migration import normalize_legacy_config
from .paths import current_config_path, legacy_sources
from .schema import ConfigCandidate, RejectedCandidate
from .storage import (
    backup_existing_config,
    read_json,
    stable_digest,
    write_json,
    write_text,
)

# Where --report writes when given no path: alongside this tool, so the report
# lands in a predictable place regardless of the caller's working directory.
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_REPORT_NAME = "migration-report.json"
DEFAULT_REPORT_PATH = PACKAGE_DIR / DEFAULT_REPORT_NAME

# Legacy key -> dotted destination path in the new config, for display.
TARGET_BY_LEGACY_KEY = {
    mapping.legacy_key: ".".join(mapping.target_path) for mapping in FIELD_MAPPINGS
}


def print_rejections(rejected: list[RejectedCandidate]) -> None:
    for item in rejected:
        print(f"Rejected {item.source} config at {item.path}: {item.error}")


def print_ambiguous(candidates: list[ConfigCandidate]) -> None:
    print("Multiple different legacy configs were found. Refusing to guess.")
    for candidate in candidates:
        print(
            f"- {candidate.source}: {candidate.path} (modified {candidate.modified.isoformat(timespec='seconds')})"
        )
    hint = ", ".join(f"--source {source.name}" for source in legacy_sources())
    print(f"Run again with {hint}, or --source-path <path>.")


def print_dropped_notes() -> None:
    for key, note in DROPPED_FIELD_NOTES.items():
        print(f"Dropped {key}: {note}")


def print_migrated_keys(candidate: ConfigCandidate) -> None:
    if not candidate.migrated_keys:
        print("Migrated 0 legacy keys: (none)")
        return
    print(f"Migrated {len(candidate.migrated_keys)} legacy keys:")
    width = max(len(key) for key in candidate.migrated_keys)
    for key in candidate.migrated_keys:
        target = TARGET_BY_LEGACY_KEY.get(key, "?")
        print(f"  {key.ljust(width)} -> {target}")


def print_unmapped_keys(candidate: ConfigCandidate) -> None:
    if not candidate.unmapped_keys:
        return
    print(f"Unmapped legacy keys in {candidate.source}: {', '.join(candidate.unmapped_keys)}")


def build_report(candidate: ConfigCandidate, destination_path: Path) -> dict[str, Any]:
    return {
        "source": candidate.source,
        "source_path": str(candidate.path),
        "destination": str(destination_path),
        "migrated_keys": list(candidate.migrated_keys),
        "dropped": {key: DROPPED_FIELD_NOTES[key] for key in candidate.dropped_keys},
        "unmapped_keys": list(candidate.unmapped_keys),
    }


def _bullets(items: list[str]) -> list[str]:
    return [f"  - {item}" for item in items] if items else ["  (none)"]


def format_report_text(report: dict[str, Any]) -> str:
    dropped = [f"{key}: {note}" for key, note in report["dropped"].items()]
    lines = [
        f"Source: {report['source']} ({report['source_path']})",
        f"Destination: {report['destination']}",
        "",
        "Migrated legacy keys:",
        *_bullets(report["migrated_keys"]),
        "",
        "Dropped legacy keys (no AETHER Next setting yet):",
        *_bullets(dropped),
        "",
        "Unmapped legacy keys:",
        *_bullets(report["unmapped_keys"]),
    ]
    return "\n".join(lines) + "\n"


def write_migration_report(path: Path, candidate: ConfigCandidate, destination_path: Path) -> bool:
    """Write the migration report. Returns False (without raising) if the file
    could not be written, so a report problem never aborts the migration."""
    report = build_report(candidate, destination_path)
    try:
        if path.suffix.lower() == ".txt":
            write_text(path, format_report_text(report))
        else:
            write_json(path, report)
    except OSError as e:
        print(f"Failed to write migration report to {path}: {e}", file=sys.stderr)
        return False
    print(f"Wrote migration report to: {path.resolve()}")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate a legacy AETHER-IDA config into AETHER Next."
    )
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--source",
        choices=tuple(source.name for source in legacy_sources()),
        help="Legacy config family to migrate when more than one exists.",
    )
    source_group.add_argument(
        "--source-path", type=Path, help="Specific legacy config.json path to migrate."
    )
    parser.add_argument(
        "--destination-path",
        type=Path,
        default=None,
        help="AETHER Next config path to write. Defaults to the AETHER Next global config path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be migrated without writing files.",
    )
    parser.add_argument(
        "--dropped",
        action="store_true",
        help="Print legacy fields intentionally dropped because AETHER Next has no static setting yet.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        nargs="?",
        const=DEFAULT_REPORT_PATH,
        default=None,
        help=(
            "Write a report of migrated, dropped, and unmapped legacy keys. "
            f"Omit the path to write {DEFAULT_REPORT_NAME} into the migrate_legacy_config directory. "
            "Use a .txt path for a human-readable report; any other suffix writes JSON."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    candidates, rejected = discover_candidates(args.source, args.source_path)
    print_rejections(rejected)

    selected = choose_candidate(candidates)
    if selected is None:
        if candidates:
            print_ambiguous(candidates)
        else:
            print("No valid legacy AETHER-IDA config was found.")
        return 1

    destination_path = args.destination_path or current_config_path()
    print(f"Selected {selected.source} config: {selected.path}")
    print(f"Destination: {destination_path}")
    print_migrated_keys(selected)
    print_unmapped_keys(selected)

    if args.dropped:
        print_dropped_notes()

    # A failed report is non-fatal (the migration still runs), but it was
    # explicitly requested, so surface it through the exit code.
    exit_code = 0
    if args.report is not None and not write_migration_report(
        args.report, selected, destination_path
    ):
        exit_code = 1

    if destination_path.is_file():
        try:
            existing = normalize_legacy_config(read_json(destination_path)).config
        except Exception:
            existing = None

        if existing is not None and stable_digest(existing) == selected.digest:
            print("Destination already matches the selected legacy config.")
            return exit_code

    if args.dry_run:
        print("Dry run complete. No files were changed.")
        return exit_code

    backup_path = backup_existing_config(destination_path)
    if backup_path is not None:
        print(f"Backed up existing config to: {backup_path}")

    write_json(destination_path, selected.config)
    print("Migration complete.")
    return exit_code
