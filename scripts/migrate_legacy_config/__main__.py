import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path


def user_data_dir(appname: str, appauthor: str | None) -> Path:
    """Stdlib port of ``platformdirs.user_data_dir`` for the platforms AETHER
    supports (Windows and Linux), so the tool stays dependency-free but resolves
    to the same paths the app uses. On Linux ``appauthor`` is not part of the path."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / appauthor / appname if appauthor else base / appname
    if sys.platform.startswith("linux"):
        # XDG Base Directory spec.
        xdg = os.environ.get("XDG_DATA_HOME", "").strip()
        return (Path(xdg) if xdg else Path.home() / ".local" / "share") / appname
    sys.exit(f"Unsupported platform {sys.platform!r}; this tool supports Windows and Linux.")


LEGACY_PATH = user_data_dir("AETHER-IDA", None) / "config.json"
DEST = user_data_dir("_global", "AETHER-next") / "config.json"

# Legacy flat key -> dotted path in the new nested config. The only thing that
# has to be declared by hand; the conversion rules and the skipped set below are
# derived, not listed.
MAPPING = {
    "OPENAI_BASE_URL": "provider.gateway_url",
    "OPENAI_API_KEY": "provider.api_key",
    "OPENAI_MODEL": "provider.default_model",
    "OPENAI_EXTRA_BODY": "provider.extra_body",
    "MODEL_LIST": "provider.models",
    "GATHERER_MODEL": "subagents.gatherer_model",
    "ANNOTATOR_MODEL": "subagents.annotator_model",
    "SINGLE_ANALYSIS_MODEL": "subagents.single_analysis_model",
    "STRUCT_CREATOR_MODEL": "subagents.struct_creator_model",
    "INDEX_AGENT_MODEL": "subagents.index_agent_model",
    "DEBUG": "debug",
    "CLIENT_CERT_PATH": "tls.client_cert_path",
    "CLIENT_KEY_PATH": "tls.client_key_path",
}


def assign(root: dict, dotted: str, value: object) -> None:
    *parents, leaf = dotted.split(".")
    for part in parents:
        root = root.setdefault(part, {})
    root[leaf] = value


if not LEGACY_PATH.is_file():
    sys.exit(f"No legacy AETHER-IDA config at {LEGACY_PATH}")

legacy = json.loads(LEGACY_PATH.read_text("utf-8"))
id_to_name = {mid: name for name, mid in legacy.get("MODEL_LIST", {}).items()}

new: dict = {}
for key, dotted in MAPPING.items():
    if key not in legacy:
        continue
    value = legacy[key]
    if key.endswith("_MODEL"):  # legacy stores model ids; new config uses friendly names
        value = id_to_name.get(value, value)
    elif key.endswith("_PATH") and value == "":
        value = None
    assign(new, dotted, value)

# Enough validation that AETHER Next can load the result (it does the full
# pydantic validation itself on startup).
provider = new.get("provider", {})
models = provider.get("models", {})
if not provider.get("gateway_url"):
    sys.exit("Legacy config is missing OPENAI_BASE_URL.")
if provider.get("default_model") not in models:
    sys.exit(f"Default model {provider.get('default_model')!r} is not in MODEL_LIST.")
for name, model in (new.get("subagents") or {}).items():
    if model is not None and model not in models:
        sys.exit(f"Subagent {name!r} uses model {model!r} which is not in MODEL_LIST.")

if DEST.is_file():
    # Timestamped so re-running never clobbers an earlier backup.
    backup = DEST.with_name(f"{DEST.name}.bak-{datetime.now():%Y%m%d%H%M%S}")
    shutil.copy2(DEST, backup)
    print(f"Backed up {DEST} -> {backup}")

DEST.parent.mkdir(parents=True, exist_ok=True)
DEST.write_text(json.dumps(new, indent=2), "utf-8")

print(f"Migrated {LEGACY_PATH} -> {DEST}")
for key in MAPPING:
    if key in legacy:
        print(f"  {key} -> {MAPPING[key]}")
skipped = sorted(set(legacy) - set(MAPPING))
if skipped:
    print("Skipped (not used by AETHER Next):", ", ".join(skipped))
