from datetime import datetime
from pathlib import Path

from .migration import normalize_legacy_config
from .paths import legacy_sources
from .schema import ConfigCandidate, RejectedCandidate
from .storage import read_json, stable_digest


def load_candidate(source: str, path: Path) -> ConfigCandidate:
    result = normalize_legacy_config(read_json(path))
    stat = path.stat()
    return ConfigCandidate(
        source=source,
        path=path,
        config=result.config,
        digest=stable_digest(result.config),
        modified=datetime.fromtimestamp(stat.st_mtime),
        migrated_keys=result.migrated_keys,
        dropped_keys=result.dropped_keys,
        unmapped_keys=result.unmapped_keys,
    )


def discover_candidates(
    source: str | None, source_path: Path | None
) -> tuple[list[ConfigCandidate], list[RejectedCandidate]]:
    candidates: list[ConfigCandidate] = []
    rejected: list[RejectedCandidate] = []

    if source_path is not None:
        if not source_path.is_file():
            rejected.append(RejectedCandidate("custom", source_path, "file does not exist"))
            return candidates, rejected
        try:
            candidates.append(load_candidate("custom", source_path))
        except Exception as e:
            rejected.append(RejectedCandidate("custom", source_path, str(e)))
        return candidates, rejected

    selected_sources = [item for item in legacy_sources() if source in (None, item.name)]
    for item in selected_sources:
        if not item.path.is_file():
            continue

        try:
            candidates.append(load_candidate(item.name, item.path))
        except Exception as e:
            rejected.append(RejectedCandidate(item.name, item.path, str(e)))

    return candidates, rejected


def choose_candidate(candidates: list[ConfigCandidate]) -> ConfigCandidate | None:
    if not candidates:
        return None

    digests = {candidate.digest for candidate in candidates}
    if len(digests) == 1:
        return sorted(candidates, key=lambda candidate: candidate.modified, reverse=True)[0]

    return None
