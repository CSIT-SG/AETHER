import copy
from typing import Any

from .mapping import DROPPED_FIELD_NOTES, FIELD_MAPPINGS, FLAT_LEGACY_SENTINEL_KEYS
from .schema import MigrationContext, MigrationResult, TargetPath
from .workspace import ensure_utils_src_on_path

ensure_utils_src_on_path()

from aether_utils.config.constants import (  # noqa: E402
    DEFAULT_CONFIG,
    DEFAULT_OPENROUTER_GATEWAY_URL,
)
from aether_utils.config.models import ConfigModel  # noqa: E402


def set_path(raw: dict[str, Any], path: TargetPath, value: Any) -> None:
    target = raw
    for part in path[:-1]:
        child = target.setdefault(part, {})
        if not isinstance(child, dict):
            raise ValueError(f"Cannot write nested config path {'.'.join(path)}")
        target = child
    target[path[-1]] = value


def is_flat_legacy_config(raw: dict[str, Any]) -> bool:
    return any(key in raw for key in FLAT_LEGACY_SENTINEL_KEYS)


def ensure_provider_defaults(raw: dict[str, Any], ctx: MigrationContext) -> None:
    provider = raw.setdefault("provider", {})
    if not isinstance(provider, dict):
        raise ValueError("provider must be an object")

    if not ctx.models:
        ctx.models.update(DEFAULT_CONFIG.provider.models)

    provider["models"] = copy.deepcopy(ctx.models)
    provider.setdefault("gateway_url", DEFAULT_OPENROUTER_GATEWAY_URL)
    provider.setdefault("api_key", "")

    default_model = provider.get("default_model")
    if default_model not in ctx.models:
        fallback = DEFAULT_CONFIG.provider.default_model
        provider["default_model"] = fallback if fallback in ctx.models else next(iter(ctx.models))


def migrate_flat_legacy_config(raw: dict[str, Any]) -> MigrationResult:
    ctx = MigrationContext(models={})
    migrated: dict[str, Any] = {}
    mapped_keys: set[str] = set()

    for mapping in FIELD_MAPPINGS:
        if mapping.legacy_key not in raw:
            continue
        set_path(migrated, mapping.target_path, mapping.convert(raw[mapping.legacy_key], ctx))
        mapped_keys.add(mapping.legacy_key)

    ensure_provider_defaults(migrated, ctx)
    config = ConfigModel.model_validate(migrated)
    dropped_keys = set(raw) & set(DROPPED_FIELD_NOTES)
    unmapped_keys = set(raw) - mapped_keys - dropped_keys
    return MigrationResult(
        config=config.model_dump(),
        migrated_keys=tuple(sorted(mapped_keys)),
        dropped_keys=tuple(sorted(dropped_keys)),
        unmapped_keys=tuple(sorted(unmapped_keys)),
    )


def normalize_nested_config(raw: dict[str, Any]) -> dict[str, Any]:
    migrated = copy.deepcopy(raw)
    provider = migrated.get("provider")

    if isinstance(provider, dict) and "gateway_url" not in provider:
        provider_type = provider.get("type")
        provider["gateway_url"] = (
            DEFAULT_OPENROUTER_GATEWAY_URL if provider_type in (None, "openrouter") else ""
        )

    config = ConfigModel.model_validate(migrated)
    return config.model_dump()


def normalize_legacy_config(raw: dict[str, Any]) -> MigrationResult:
    if is_flat_legacy_config(raw):
        return migrate_flat_legacy_config(raw)
    # A nested config is already in AETHER Next shape; nothing is mapped or dropped.
    return MigrationResult(
        config=normalize_nested_config(raw),
        migrated_keys=(),
        dropped_keys=(),
        unmapped_keys=(),
    )
