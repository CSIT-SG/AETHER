"""
Core data classes for the function index: FunctionEntry, BatchMetadata,
FunctionIndex.

Handles JSON serialisation / deserialisation and atomic file persistence.
"""

import base64
import json
import os
import re as _re
import threading
import time
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .function_tagger import (
    IMPORTANCE_ORDER,
    ImportanceLevel,
    importance_at_or_above,
    is_importance_tag,
)


def _normalize_address_key(addr: Any) -> str:
    if isinstance(addr, int):
        return f"0x{addr:08x}"
    addr = str(addr or "").strip()
    if not addr:
        return ""
    if addr.lower().startswith("0x"):
        addr = addr[2:]
    try:
        value = int(addr, 16)
    except Exception:
        return "0x" + addr.lower()
    return f"0x{value:08x}"


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
    phase: str = "PENDING"
    decompiled_count: int = 0
    decompile_ok_count: int = 0
    decompile_skip_count: int = 0
    decompile_fail_count: int = 0
    current_function_ea: Optional[str] = None
    current_function_name: Optional[str] = None
    current_function_started_ms: int = 0
    current_function_elapsed_s: int = 0
    slow_decompile_threshold_s: int = 5
    slow_decompile_functions: List[dict] = field(default_factory=list)
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
            "phase": self.phase,
            "decompiled_count": self.decompiled_count,
            "decompile_ok_count": self.decompile_ok_count,
            "decompile_skip_count": self.decompile_skip_count,
            "decompile_fail_count": self.decompile_fail_count,
            "current_function_ea": self.current_function_ea,
            "current_function_name": self.current_function_name,
            "current_function_started_ms": self.current_function_started_ms,
            "current_function_elapsed_s": self.current_function_elapsed_s,
            "slow_decompile_threshold_s": self.slow_decompile_threshold_s,
            "slow_decompile_functions": list(self.slow_decompile_functions),
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
        bm.phase = d.get("phase", "PENDING")
        bm.decompiled_count = d.get("decompiled_count", 0)
        bm.decompile_ok_count = d.get("decompile_ok_count", 0)
        bm.decompile_skip_count = d.get("decompile_skip_count", 0)
        bm.decompile_fail_count = d.get("decompile_fail_count", 0)
        bm.current_function_ea = d.get("current_function_ea")
        bm.current_function_name = d.get("current_function_name")
        bm.current_function_started_ms = d.get("current_function_started_ms", 0)
        bm.current_function_elapsed_s = d.get("current_function_elapsed_s", 0)
        bm.slow_decompile_threshold_s = int(d.get("slow_decompile_threshold_s", 5))
        bm.slow_decompile_functions = list(d.get("slow_decompile_functions", []))
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

    INDEX_VERSION = 4

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
        # Compressed pseudocode cache: {"0x401000": "<base64(zlib(bytes))>"}
        self.pseudocode_cache: Dict[str, str] = OrderedDict()
        # Decompile blacklist: {"0x401000": {"name": "func", "reason": "size_limit"}}
        self.decompile_blacklist: Dict[str, dict] = OrderedDict()
        # LLM parse failures: {"0x401000": {"name": "func", "batch": 3, "reason": "missing_from_response"}}
        self.llm_failed_entries: Dict[str, dict] = OrderedDict()

        # Thread safety for merge_and_persist
        self._lock = threading.Lock()

    # -- Entry management --

    def add_entry(self, entry: FunctionEntry) -> None:
        self.entries_by_address[entry.address] = entry
        self.entries_by_name[entry.name] = entry
        # If an entry exists, clear any recorded LLM failure for it.
        addr_key = (entry.address or "").strip().lower()
        if addr_key:
            self.llm_failed_entries.pop(addr_key, None)

    # -- Decompile blacklist --

    def add_decompile_skip(self, addr: str, name: str, reason: str) -> None:
        if not addr:
            return
        addr_key = addr.strip().lower()
        self.decompile_blacklist[addr_key] = {
            "name": name or "",
            "reason": reason or "unknown",
        }

    def is_decompile_blacklisted(self, addr: str) -> bool:
        if not addr:
            return False
        return addr.strip().lower() in self.decompile_blacklist

    # -- LLM parse failures --

    def add_llm_failure(self, addr: str, name: str, batch: int, reason: str) -> None:
        if not addr:
            return
        addr_key = addr.strip().lower()
        self.llm_failed_entries[addr_key] = {
            "name": name or "",
            "batch": int(batch) if batch else 0,
            "reason": reason or "unknown",
        }

    def normalize_llm_failures(self) -> bool:
        normalized = OrderedDict()
        changed = False
        indexed_keys = {
            _normalize_address_key(addr)
            for addr in self.entries_by_address.keys()
            if _normalize_address_key(addr)
        }

        for addr_key, data in self.llm_failed_entries.items():
            norm_key = _normalize_address_key(str(addr_key))
            if not norm_key:
                changed = True
                continue
            if norm_key in indexed_keys:
                changed = True
                continue

            existing = normalized.get(norm_key)
            if existing is None:
                if norm_key != str(addr_key).strip().lower():
                    changed = True
                normalized[norm_key] = data
                continue

            try:
                existing_batch = int(existing.get("batch", 0))
            except Exception:
                existing_batch = 0
            try:
                new_batch = int(data.get("batch", 0))
            except Exception:
                new_batch = 0

            if new_batch > existing_batch:
                normalized[norm_key] = data
                changed = True

        if changed:
            self.llm_failed_entries = OrderedDict(normalized)
        return changed

    # -- Pseudocode cache --

    def set_pseudocode_cache(self, addr: str, text: str) -> bool:
        """Store compressed pseudocode for *addr*.

        Returns True on success.
        """
        if not addr or not text:
            return False
        addr_key = addr.strip().lower()
        try:
            raw = text.encode("utf-8", errors="replace")
            compressed = zlib.compress(raw, level=6)
            payload = base64.b64encode(compressed).decode("ascii")
            self.pseudocode_cache[addr_key] = payload
            return True
        except Exception:
            return False

    def get_pseudocode_cache(self, addr: str) -> Optional[str]:
        """Return cached pseudocode for *addr* if present."""
        if not addr:
            return None
        addr_key = addr.strip().lower()
        payload = self.pseudocode_cache.get(addr_key)
        if not payload:
            return None
        try:
            compressed = base64.b64decode(payload)
            raw = zlib.decompress(compressed)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

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
        if self.indexing_state not in ("PARTIAL", "FAILED", "IN_PROGRESS"):
            return False

        if self.batch_metadata.completed_batches < self.batch_metadata.total_batches:
            return True

        # Decompilation-stage cancellation may happen before batch metadata is initialized.
        if self.batch_metadata.phase in ("DECOMPILING", "CANCELLED", "PAUSED_DECOMP", "PAUSED_INDEXING"):
            return True

        if self.batch_metadata.decompiled_count > 0:
            return True

        return False

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
            "pseudocode_cache": dict(self.pseudocode_cache),
            "decompile_blacklist": dict(self.decompile_blacklist),
            "llm_failed_entries": dict(self.llm_failed_entries),
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
        idx = FunctionIndex.load_from_file(filepath)
        if idx is not None:
            if idx.normalize_llm_failures():
                idx.save_to_file(filepath)
            return idx

        legacy_path = _get_legacy_index_filepath(identifier)
        idx = FunctionIndex.load_from_file(legacy_path)
        if idx is None:
            return None

        try:
            idx.normalize_llm_failures()
            idx.save_to_file(filepath)
            os.remove(legacy_path)
        except Exception:
            pass
        return idx

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
        idx.pseudocode_cache = OrderedDict(data.get("pseudocode_cache", {}))
        idx.decompile_blacklist = OrderedDict(data.get("decompile_blacklist", {}))
        idx.llm_failed_entries = OrderedDict(data.get("llm_failed_entries", {}))

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

def _get_index_base_dir() -> str:
    import sys
    if sys.platform == "win32":
        appdata = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
        return os.path.join(appdata, "AETHER-IDA", "indexes")
    return os.path.join(os.path.expanduser("~"), ".idapro", "ainalyse-indexes")


def _get_index_dir(identifier: str) -> str:
    """Compute the standard index directory path for *identifier*."""
    return os.path.join(_get_index_base_dir(), identifier)


def _get_legacy_index_filepath(identifier: str) -> str:
    """Legacy index file path (before per-binary folders)."""
    return os.path.join(_get_index_base_dir(), f"{identifier}.json")


def _get_index_filepath(identifier: str) -> str:
    """Compute the standard index file path for *identifier*."""
    return os.path.join(_get_index_dir(identifier), "index.json")


def get_index_filepath(identifier: str) -> str:
    """Public accessor for index filepath (used by manager)."""
    return _get_index_filepath(identifier)


def get_index_dir(identifier: str) -> str:
    """Public accessor for index directory (used by manager/logging)."""
    return _get_index_dir(identifier)


def get_index_base_dir() -> str:
    """Public accessor for the base index directory."""
    return _get_index_base_dir()


def get_legacy_index_filepath(identifier: str) -> str:
    """Public accessor for legacy index filepath."""
    return _get_legacy_index_filepath(identifier)


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
