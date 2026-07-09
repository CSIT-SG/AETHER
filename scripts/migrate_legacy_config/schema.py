from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LegacySource:
    name: str
    path: Path


@dataclass(frozen=True)
class MigrationResult:
    config: dict[str, Any]
    # Legacy keys that were carried into the new config.
    migrated_keys: tuple[str, ...]
    # Legacy keys present in the source but intentionally dropped (in DROPPED_FIELD_NOTES).
    dropped_keys: tuple[str, ...]
    # Legacy keys we neither mapped nor knowingly dropped.
    unmapped_keys: tuple[str, ...]


@dataclass(frozen=True)
class ConfigCandidate:
    source: str
    path: Path
    config: dict[str, Any]
    digest: str
    modified: datetime
    migrated_keys: tuple[str, ...]
    dropped_keys: tuple[str, ...]
    unmapped_keys: tuple[str, ...]


@dataclass(frozen=True)
class RejectedCandidate:
    source: str
    path: Path
    error: str


@dataclass
class MigrationContext:
    models: dict[str, str]


type TargetPath = tuple[str, ...]
type Converter = Callable[[Any, MigrationContext], Any]


@dataclass(frozen=True)
class FieldMapping:
    legacy_key: str
    target_path: TargetPath
    convert: Converter
