"""
Core data classes for the function index: FunctionEntry, BatchMetadata,
FunctionIndex.

Handles JSON serialisation / deserialisation and atomic file persistence.
"""

import json
import os
import re as _re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from .function_tagger import (
    IMPORTANCE_ORDER,
    ImportanceLevel,
    importance_at_or_above,
    is_importance_tag,
)


# ---------------------------------------------------------------------------
# BatchMetadata
# ---------------------------------------------------------------------------

@dataclass
class BatchMetadata:
    """Tracks progress across LLM classification batches."""
    indexed_functions: int = 0
    total_batches: int = 0
    completed_batches: int = 0
    current_batch: int = 0
    start_time: int = 0          # ms since epoch
    last_update_time: int = 0    # ms since epoch
    last_error: Optional[str] = None
    batch_token_counts: List[int] = field(default_factory=list)

    def total_tokens(self) -> int:
        return sum(self.batch_token_counts)

    # -- Serialisation helpers --

    def to_dict(self) -> dict:
        d: dict = {
            "indexed_functions": self.indexed_functions,
            "total_batches": self.total_batches,
            "completed_batches": self.completed_batches,
            "current_batch": self.current_batch,
            "start_time": self.start_time,
            "start_time_readable": _ms_readable(self.start_time),
            "last_update_time": self.last_update_time,
            "last_update_readable": _ms_readable(self.last_update_time),
            "total_tokens": self.total_tokens(),
            "batch_token_counts": list(self.batch_token_counts),
            "last_error": self.last_error,
        }
        return d

    @staticmethod
    def from_dict(d: dict) -> "BatchMetadata":
        bm = BatchMetadata()
        bm.indexed_functions = d.get("indexed_functions", 0)
        bm.total_batches = d.get("total_batches", 0)
        bm.completed_batches = d.get("completed_batches", 0)
        bm.current_batch = d.get("current_batch", 0)
        bm.start_time = d.get("start_time", 0)
        bm.last_update_time = d.get("last_update_time", 0)
        bm.last_error = d.get("last_error")
        bm.batch_token_counts = list(d.get("batch_token_counts", []))
        return bm


# ---------------------------------------------------------------------------
# FunctionEntry
# ---------------------------------------------------------------------------

@dataclass
class FunctionEntry:
    """A single indexed function."""
    name: str
    address: str                                    # "0x00401000" format
    tags: Set[str] = field(default_factory=set)     # Mix of importance + category tags
    summary: str = ""
    callee_functions: List[str] = field(default_factory=list)
    key_operations: List[str] = field(default_factory=list)
    key_constants: List[str] = field(default_factory=list)
    called_apis: List[str] = field(default_factory=list)

    # -- Querying helpers --

    def get_importance_level(self) -> Optional[str]:
        """Extract the importance tag (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL)."""
        for tag in self.tags:
            if is_importance_tag(tag):
                return tag.upper()
        return None

    def get_functional_categories(self) -> Set[str]:
        """All tags that are *not* importance levels."""
        return {t for t in self.tags if not is_importance_tag(t)}

    def get_routing_description(self) -> str:
        """Concatenate summary + ops + constants + APIs for search."""
        parts = [self.summary]
        if self.key_operations:
            parts.append("Operations: " + ", ".join(self.key_operations))
        if self.key_constants:
            parts.append("Constants: " + ", ".join(self.key_constants))
        if self.called_apis:
            parts.append("APIs: " + ", ".join(self.called_apis))
        return " | ".join(parts)

    def matches_keyword(self, keyword: str) -> bool:
        """Case-insensitive keyword search across all fields."""
        kw = keyword.lower()
        if kw in self.name.lower():
            return True
        if kw in self.address.lower():
            return True
        if kw in self.summary.lower():
            return True
        for tag in self.tags:
            if kw in tag.lower():
                return True
        for lst in (self.callee_functions, self.key_operations, self.key_constants, self.called_apis):
            for item in lst:
                if kw in item.lower():
                    return True
        return False

    # -- Serialisation --

    def to_dict(self, include_metadata: bool = True) -> dict:
        d: dict = {
            "name": self.name,
            "address": self.address,
            "tags": sorted(self.tags),
            "summary": self.summary,
            "callee_functions": list(self.callee_functions),
        }
        if include_metadata:
            d["key_operations"] = list(self.key_operations)
            d["key_constants"] = list(self.key_constants)
            d["called_apis"] = list(self.called_apis)
        return d

    @staticmethod
    def from_dict(d: dict) -> "FunctionEntry":
        return FunctionEntry(
            name=d.get("name", ""),
            address=d.get("address", ""),
            tags=set(d.get("tags", [])),
            summary=d.get("summary", ""),
            callee_functions=list(d.get("callee_functions", [])),
            key_operations=list(d.get("key_operations", [])),
            key_constants=list(d.get("key_constants", [])),
            called_apis=list(d.get("called_apis", [])),
        )


# ---------------------------------------------------------------------------
# FunctionIndex
# ---------------------------------------------------------------------------

class FunctionIndex:
    """Master index of all classified functions for a binary."""

    INDEX_VERSION = 2

    def __init__(self) -> None:
        self.entries_by_address: Dict[str, FunctionEntry] = OrderedDict()
        self.entries_by_name: Dict[str, FunctionEntry] = {}
        self.timestamp: int = _now_ms()
        self.indexed: bool = False
        self.sha256: Optional[str] = None
        self.program_name: Optional[str] = None
        self.total_function_count: int = 0
        self.last_indexed_address: Optional[str] = None
        self.indexing_progress: int = 0
        self.indexing_state: str = "PENDING"
        self.batch_metadata: BatchMetadata = BatchMetadata()
        self.total_tokens_used: int = 0
        self.dynamic_tags: Dict[str, dict] = OrderedDict()

        # Thread safety for merge_and_persist
        self._lock = threading.Lock()

    # -- Entry management --

    def add_entry(self, entry: FunctionEntry) -> None:
        self.entries_by_address[entry.address] = entry
        self.entries_by_name[entry.name] = entry

    def get_entry_by_address(self, addr: str) -> Optional[FunctionEntry]:
        return self.entries_by_address.get(addr)

    def get_entry_by_name(self, name: str) -> Optional[FunctionEntry]:
        return self.entries_by_name.get(name)

    # -- Filtering --

    def get_entries_by_importance(self, min_level: str) -> List[FunctionEntry]:
        """Return entries whose importance is ≥ *min_level*."""
        return [
            e for e in self.entries_by_address.values()
            if e.get_importance_level() and importance_at_or_above(e.get_importance_level(), min_level)
        ]

    def get_entries_with_tag(self, tag: str) -> List[FunctionEntry]:
        tag_lower = tag.lower()
        return [e for e in self.entries_by_address.values() if tag_lower in {t.lower() for t in e.tags}]

    # -- State queries --

    def size(self) -> int:
        return len(self.entries_by_address)

    def is_empty(self) -> bool:
        return self.size() == 0

    def is_usable_for_queries(self) -> bool:
        return not self.is_empty() and self.indexing_state in ("COMPLETED", "IN_PROGRESS", "PARTIAL")

    def is_resumable(self) -> bool:
        return (
            self.indexing_state in ("PARTIAL", "FAILED", "IN_PROGRESS")
            and self.batch_metadata.completed_batches < self.batch_metadata.total_batches
        )

    def get_resume_point(self) -> int:
        """1-based batch number to resume from."""
        return self.batch_metadata.completed_batches + 1

    def get_indexed_addresses(self) -> Set[str]:
        return set(self.entries_by_address.keys())

    # -- Merge --

    def merge(self, other: "FunctionIndex") -> None:
        """Merge entries from *other* into this index (other wins on conflict)."""
        for entry in other.entries_by_address.values():
            self.add_entry(entry)

    def merge_and_persist(
        self,
        batch_entries: List[FunctionEntry],
        batch_number: int,
        total_batches: int,
        batch_tokens: int = 0,
    ) -> bool:
        """Thread-safe merge of a batch result + atomic save.

        Returns ``True`` on success.
        """
        with self._lock:
            for entry in batch_entries:
                self.add_entry(entry)

            self.batch_metadata.completed_batches = batch_number
            self.batch_metadata.current_batch = batch_number
            self.batch_metadata.total_batches = total_batches
            self.batch_metadata.indexed_functions = self.size()
            self.batch_metadata.last_update_time = _now_ms()
            if batch_tokens:
                self.batch_metadata.batch_token_counts.append(batch_tokens)
            self.total_tokens_used = self.batch_metadata.total_tokens()

            if batch_entries:
                self.last_indexed_address = batch_entries[-1].address

            self.indexing_progress = int(batch_number / max(total_batches, 1) * 100)
            self.timestamp = _now_ms()

            return self.save_to_file()

    # -- JSON serialisation --

    def to_json(self, include_metadata: bool = True) -> str:
        if include_metadata:
            data = self._to_full_dict()
        else:
            data = self._to_compact_dict()
        return _compact_json_dumps(data)

    def _to_full_dict(self) -> dict:
        return {
            "index_version": self.INDEX_VERSION,
            "sha256": self.sha256,
            "program_name": self.program_name,
            "timestamp": self.timestamp,
            "timestamp_readable": _ms_readable(self.timestamp),
            "indexed": self.indexed,
            "indexing_state": self.indexing_state,
            "total_function_count": self.total_function_count,
            "indexed_function_count": self.size(),
            "indexing_progress": self.indexing_progress,
            "total_tokens_used": self.total_tokens_used,
            "last_indexed_address": self.last_indexed_address,
            "batch_metadata": self.batch_metadata.to_dict(),
            "dynamic_tags": dict(self.dynamic_tags),
            "functions": [e.to_dict(include_metadata=True) for e in self.entries_by_address.values()],
        }

    def _to_compact_dict(self) -> dict:
        return {
            "functions": [e.to_dict(include_metadata=False) for e in self.entries_by_address.values()],
        }

    # -- File persistence (atomic write) --

    def save_to_file(self, filepath: Optional[str] = None) -> bool:
        """Atomic write: write to ``.tmp`` then rename."""
        if filepath is None:
            if not self.sha256:
                print("[AETHER] Cannot save index: no identifier (sha256) set.")
                return False
            filepath = _get_index_filepath(self.sha256)

        index_dir = os.path.dirname(filepath)
        os.makedirs(index_dir, exist_ok=True)

        temp_file = filepath + ".tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(self.to_json(include_metadata=True))

            if os.path.exists(filepath):
                os.remove(filepath)
            os.rename(temp_file, filepath)
            return True
        except Exception as e:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
            print(f"[AETHER] Failed to save index: {e}")
            return False

    # -- Loading --

    @staticmethod
    def load_from_file(filepath: str) -> Optional["FunctionIndex"]:
        """Parse a persisted JSON index file.  Returns ``None`` on failure."""
        if not os.path.isfile(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return FunctionIndex._from_dict(data)
        except Exception as e:
            print(f"[AETHER] Failed to load index from {filepath}: {e}")
            return None

    @staticmethod
    def load_by_identifier(identifier: str) -> Optional["FunctionIndex"]:
        """Construct the standard path from an identifier and try to load."""
        filepath = _get_index_filepath(identifier)
        return FunctionIndex.load_from_file(filepath)

    @staticmethod
    def _from_dict(data: dict) -> "FunctionIndex":
        idx = FunctionIndex()
        idx.sha256 = data.get("sha256")
        idx.program_name = data.get("program_name")
        idx.timestamp = data.get("timestamp", 0)
        idx.indexed = data.get("indexed", False)
        idx.indexing_state = data.get("indexing_state", "PENDING")
        idx.total_function_count = data.get("total_function_count", 0)
        idx.indexing_progress = data.get("indexing_progress", 0)
        idx.total_tokens_used = data.get("total_tokens_used", 0)
        idx.last_indexed_address = data.get("last_indexed_address")

        bm_data = data.get("batch_metadata")
        if bm_data:
            idx.batch_metadata = BatchMetadata.from_dict(bm_data)

        idx.dynamic_tags = OrderedDict(data.get("dynamic_tags", {}))

        for fe_data in data.get("functions", []):
            entry = FunctionEntry.from_dict(fe_data)
            idx.add_entry(entry)

        return idx


# ---------------------------------------------------------------------------
# Compact JSON formatter
# ---------------------------------------------------------------------------

# Matches a JSON array whose content is short enough to inline.
_SHORT_ARRAY_RE = _re.compile(
    r"(?P<indent>[ ]*)\[(?:\s*\n(?:[ ]*(?:\"[^\"]*\"|[-\d.]+|true|false|null),?\s*\n?)*[ ]*)\]"
)


def _compact_json_dumps(data: dict, indent: int = 2, max_inline_len: int = 120) -> str:
    """Pretty-print JSON but collapse short arrays onto a single line.

    Python's ``json.dumps(indent=…)`` puts every list element on its own
    line.  This helper collapses arrays that, when written inline, would be
    shorter than *max_inline_len* characters (including the indentation).
    The result is much more compact for entries whose ``tags``,
    ``key_operations``, ``called_apis``, etc. are short lists.
    """
    raw = json.dumps(data, indent=indent, ensure_ascii=False)

    def _collapse(match: _re.Match) -> str:
        full = match.group(0)
        # Parse the array portion to get the actual values
        try:
            arr = json.loads(full.strip())
        except (json.JSONDecodeError, ValueError):
            return full
        if not isinstance(arr, list):
            return full
        inline = json.dumps(arr, ensure_ascii=False)
        # Keep the original indentation
        prefix = match.group("indent")
        candidate = prefix + inline
        if len(candidate) <= max_inline_len:
            return candidate
        return full

    # Collapse arrays that span multiple lines but are short when inlined
    result = _SHORT_ARRAY_RE.sub(_collapse, raw)
    return result


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def _get_index_filepath(identifier: str) -> str:
    """Compute the standard index file path for *identifier*."""
    import sys
    if sys.platform == "win32":
        appdata = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
        base = os.path.join(appdata, "AETHER-IDA", "indexes")
    else:
        base = os.path.join(os.path.expanduser("~"), ".idapro", "ainalyse-indexes")
    return os.path.join(base, f"{identifier}.json")


def get_index_filepath(identifier: str) -> str:
    """Public accessor for index filepath (used by manager)."""
    return _get_index_filepath(identifier)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _ms_readable(ms: int) -> str:
    if ms == 0:
        return ""
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ms)
