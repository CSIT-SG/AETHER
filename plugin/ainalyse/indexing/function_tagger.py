"""
Importance levels, functional categories, and tag normalisation utilities.

All tag resolution (exact → fuzzy → dynamic registration) lives here so that
both the indexer and the index manager can share the same logic.
"""

import re
from enum import IntEnum
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Importance levels
# ---------------------------------------------------------------------------

class ImportanceLevel(IntEnum):
    """Importance levels ranked from highest to lowest."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    MINIMAL = 1

IMPORTANCE_LEVELS = {level.name for level in ImportanceLevel}

IMPORTANCE_ORDER: Dict[str, int] = {level.name: level.value for level in ImportanceLevel}


def is_importance_tag(tag: str) -> bool:
    """Return True if *tag* is a recognised importance level (case-insensitive)."""
    return tag.upper() in IMPORTANCE_LEVELS


def importance_at_or_above(level_name: str, threshold_name: str) -> bool:
    """Return True if *level_name* meets or exceeds *threshold_name*."""
    return IMPORTANCE_ORDER.get(level_name.upper(), 0) >= IMPORTANCE_ORDER.get(threshold_name.upper(), 0)


# ---------------------------------------------------------------------------
# Default functional categories
# ---------------------------------------------------------------------------

DEFAULT_FUNCTION_TAGS: Dict[str, str] = {
    "network": "Network operations (sockets, HTTP, DNS, packet capture)",
    "crypto": "Cryptographic operations (encryption, hashing, key generation)",
    "file-io": "File system operations (read, write, create, delete)",
    "registry": "Registry operations (Windows registry read/write)",
    "process": "Process/thread management (create, inject, terminate)",
    "memory": "Memory management (allocation, mapping, protection)",
    "string-processing": "String manipulation and encoding/decoding",
    "data-structures": "Data structure operations (lists, trees, buffers)",
    "api-wrapper": "Thin wrapper around a single API call",
    "initialization": "Program/module initialization and setup",
    "cleanup": "Resource cleanup and deinitialization",
    "error-handling": "Error detection, logging, and recovery",
    "logging": "Logging, debug output, telemetry",
    "synchronization": "Locking, signaling, timing, thread sync",
    "control-flow": "Dispatch, routing, state machines, main loops",
    "execution": "Code execution (shellcode, DLL loading, eval)",
    "persistence": "Persistence mechanisms (services, run keys, tasks)",
    "discovery": "System/network reconnaissance and enumeration",
    "evasion": "Anti-analysis, anti-debug, VM detection, packing",
    "c2-communication": "Command-and-control protocol handling",
    "unknown": "Does not fit any other category (LAST RESORT only)",
}


def get_configured_tags(config: Optional[dict] = None) -> Dict[str, str]:
    """Return the function tag taxonomy from *config*, falling back to defaults."""
    if config and "function_tags" in config:
        return config["function_tags"]
    return DEFAULT_FUNCTION_TAGS.copy()


# ---------------------------------------------------------------------------
# Tag normalisation
# ---------------------------------------------------------------------------

_NORMALISE_RE_BAD_CHARS = re.compile(r"[^a-z0-9:\-]")
_NORMALISE_RE_MULTI_DASH = re.compile(r"-{2,}")


def normalize_tag_id(raw: str) -> str:
    """Normalise a raw tag string into canonical form.

    1. Strip and lowercase
    2. Replace underscores and whitespace with ``-``
    3. Remove characters outside ``[a-z0-9:-]``
    4. Collapse repeated ``-``
    5. Strip leading/trailing ``-``
    """
    tag = raw.strip().lower()
    tag = tag.replace("_", "-").replace(" ", "-")
    tag = _NORMALISE_RE_BAD_CHARS.sub("", tag)
    tag = _NORMALISE_RE_MULTI_DASH.sub("-", tag)
    tag = tag.strip("-")
    return tag


# ---------------------------------------------------------------------------
# Fuzzy matching helpers
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein distance (no third-party deps)."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur_row = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            cur_row.append(min(cur_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost))
        prev_row = cur_row
    return prev_row[-1]


def _fuzzy_match(candidate: str, known_tags: Dict[str, str]) -> Optional[str]:
    """Return the best fuzzy match against *known_tags* or ``None``.

    Match criteria (same as spec):
      - Levenshtein distance ≤ 2  **OR**
      - One is a substring of the other with ≤ 3-char length difference
    """
    for known in known_tags:
        # Levenshtein
        if _levenshtein(candidate, known) <= 2:
            return known
        # Substring with length check
        if candidate in known or known in candidate:
            if abs(len(candidate) - len(known)) <= 3:
                return known
    return None


# ---------------------------------------------------------------------------
# Tag resolution (exact → fuzzy → dynamic)
# ---------------------------------------------------------------------------

def resolve_tag(
    raw: str,
    configured_tags: Dict[str, str],
    dynamic_tag_manager: Optional[object] = None,
    function_name: str = "",
) -> Tuple[str, bool]:
    """Resolve a raw tag emitted by the LLM.

    Returns ``(normalised_tag_id, is_new_dynamic)`` where *is_new_dynamic* is
    ``True`` when the tag was registered as a brand-new dynamic tag.
    """
    tag = normalize_tag_id(raw)
    if not tag:
        return "unknown", False

    # Importance tags are passed through as-is
    if is_importance_tag(tag):
        return tag.upper(), False

    # Normalise the configured tag keys for comparison
    normalised_configured = {normalize_tag_id(k): v for k, v in configured_tags.items()}

    # 1. Exact match
    if tag in normalised_configured:
        return tag, False

    # 2. Check if the *parent* portion (before ``:``) matches a configured tag
    if ":" in tag:
        parent = tag.split(":")[0]
        if parent in normalised_configured:
            # Valid hierarchical sub-tag — keep as-is
            return tag, _maybe_register_dynamic(tag, raw, function_name, dynamic_tag_manager)

    # 3. Fuzzy match
    fuzzy = _fuzzy_match(tag, normalised_configured)
    if fuzzy is not None:
        return fuzzy, False

    # 4. No match — register as dynamic
    return tag, _maybe_register_dynamic(tag, raw, function_name, dynamic_tag_manager)


def _maybe_register_dynamic(
    tag_id: str,
    original_form: str,
    function_name: str,
    dynamic_tag_manager: Optional[object],
) -> bool:
    """Attempt to register a tag with the dynamic manager.  Returns True if new."""
    if dynamic_tag_manager is None:
        return False
    # Duck-type: call register_tag if available
    if hasattr(dynamic_tag_manager, "register_tag"):
        return dynamic_tag_manager.register_tag(tag_id, original_form, function_name)
    return False


def drop_unknown_if_redundant(tags: set) -> set:
    """Remove ``unknown`` from *tags* if other non-importance categories exist."""
    category_tags = {t for t in tags if not is_importance_tag(t)}
    if "unknown" in category_tags and len(category_tags) > 1:
        tags.discard("unknown")
    return tags
