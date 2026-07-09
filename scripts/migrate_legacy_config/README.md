# migrate_legacy_config

One-shot migration for legacy AETHER config files into the current AETHER Next config.

The tool intentionally migrates only settings that AETHER Next currently exposes as static `ConfigModel` fields and runtime-supported values: `provider`, `subagents`, `debug`, and `tls`. Legacy feature/runtime knobs that AETHER Next does not read yet are dropped on purpose instead of being copied into free-form `features` objects.

## Usage

`cd` into this directory and run the package with `python .`:

```sh
cd scripts/migrate_legacy_config

# Preview the migration without writing files.
uv run python . --source AETHER-IDA --dry-run --dropped

# Migrate a specific legacy file.
uv run python . --source-path path\to\config.json

# Write a report while previewing (omit the path to write
# migration-report.json into this directory).
uv run python . --source AETHER-IDA --dry-run --report
```

If exactly one legacy config family is present, `--source` can be omitted.

> Running from the repo root with `uv run python -m scripts.migrate_legacy_config ...` also works.

## Flags

| Flag | Purpose |
| --- | --- |
| `--source {AETHER-IDA}` | Select the legacy config family. `AETHER-IDA` is currently the only one; auto-discovery selects it when the flag is omitted. |
| `--source-path <path>` | Migrate a specific `config.json` instead of auto-discovering. |
| `--destination-path <path>` | Write to a custom destination. Defaults to the AETHER Next global config path. |
| `--dry-run` | Print what would happen without writing files. |
| `--dropped` | Print legacy fields intentionally dropped, with reasons. |
| `--report [path]` | Write migrated, dropped, and unmapped keys. Omit the path to write `migration-report.json` into this tool's directory (regardless of where you invoke it). `.txt` writes a human-readable report; other suffixes write JSON. A report that cannot be written is logged to stderr without aborting the migration. |

`--source` and `--source-path` are mutually exclusive.

## Behavior

- Discovers known legacy config locations in `paths.py`, or accepts one explicit `--source-path`.
- Converts flat legacy configs such as `OPENAI_MODEL` / `MODEL_LIST` into nested AETHER Next config.
- Resolves legacy model IDs back to friendly model names from `MODEL_LIST`, because AETHER Next validates model selections by friendly name.
- Validates the result with `ConfigModel` before writing.
- Refuses to guess when multiple different legacy configs are found. Identical configs across families are okay; the newest is used.
- Backs up an existing destination config as `config.json.bak-<timestamp>` before overwriting.
- Skips writing when the destination already matches the selected migrated config.

## Dropped Fields

AETHER Next's settings UI is generated from `ConfigModel`, but current `features` entries are free-form `dict[str, object]` buckets and are not read by runtime code. Migrating old feature knobs into those buckets would preserve text that nothing uses, so this tool drops them.

The authoritative list is `DROPPED_FIELD_NOTES` in [`mapping.py`](mapping.py). Run with `--dropped` or `--report` to see what was dropped for a source config.

When AETHER Next implements one of those settings as a static field and runtime code reads it, move the legacy key from `DROPPED_FIELD_NOTES` to `FIELD_MAPPINGS`.

## Layout

| Module | Responsibility |
| --- | --- |
| `paths.py` | Discover legacy and current config paths. |
| `mapping.py` | Legacy-to-new field mappings and dropped-field notes. |
| `migration.py` | Convert and validate configs into `ConfigModel` shape. |
| `candidates.py` | Discover candidates and resolve ambiguity. |
| `storage.py` | JSON read/write, hashing, and backup. |
| `cli.py` | Command-line behavior and reports. |
| `schema.py` | Shared dataclasses. |
| `tests/test_migration.py` | In-memory migration, ambiguity, and backup tests. |

## Tests

```sh
uv run pytest scripts/migrate_legacy_config/tests/test_migration.py
```
