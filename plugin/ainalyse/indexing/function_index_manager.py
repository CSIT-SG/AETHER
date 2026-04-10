"""
Persistence layer, in-memory cache, and staleness detection for function
indexes.

Also houses ``get_program_identifier()`` which produces the stable,
content-based key used to name index files.
"""

import hashlib
import os
import threading
import time
from typing import Dict, Optional

import ida_kernwin
import ida_nalt
import idc
import idautils

from .function_index import FunctionIndex, get_index_filepath


import hashlib
import os
import threading
import time
from typing import Dict, Optional

import idaapi
import ida_kernwin
import ida_nalt
import idc
import idautils

from .function_index import FunctionIndex, get_index_filepath


# ---------------------------------------------------------------------------
# Netnode-backed identifier
# ---------------------------------------------------------------------------

_NETNODE_INDEX_ID = "$ainalyse.index_id.v1"


def _run_on_main_thread(func):
    """Execute *func* on the IDA main thread and return its result.

    If already on the main thread the function is called directly.
    """
    if threading.current_thread() is threading.main_thread():
        return func()

    container = {"result": None}

    def _wrapper():
        container["result"] = func()
        return 1  # execute_sync expects an int return

    ida_kernwin.execute_sync(_wrapper, ida_kernwin.MFF_READ)
    return container["result"]


# ---------------------------------------------------------------------------
# Stable binary identifier
# ---------------------------------------------------------------------------

def get_program_identifier() -> str:
    """Return a stable unique identifier for the current binary/IDB.

    Strategy (all steps execute on the main thread):
      1. Check the IDB netnode for a previously persisted identifier.
         If found, return it immediately.  This is the fast path for any
         IDB that has been saved at least once after indexing.
      2. Derive an identifier from the original input file:
         a. SHA256 (``ida_nalt.retrieve_input_file_sha256``)
         b. MD5 (``idautils.GetInputFileMD5``)
         c. IDB path hash (last resort)
      3. Store the derived identifier in the netnode so future calls
         (even from background threads) are consistent.

    The netnode is created in-memory even before the user saves the IDB,
    so no "save first" precondition exists.  If the user closes without
    saving, step 2 will re-derive the same hash on next open.

    Safe to call from any thread.
    """
    def _identify():
        # 1. Check netnode for a stored identifier
        try:
            nn = idaapi.netnode(_NETNODE_INDEX_ID, 0, True)
            blob = nn.getblob(0, "B")
            if blob:
                stored = blob.decode("utf-8", errors="replace").strip()
                if stored:
                    return stored
        except Exception:
            pass

        # 2. Derive from input file hashes
        identifier: Optional[str] = None

        # 2a. SHA256 of original input file
        try:
            sha256 = ida_nalt.retrieve_input_file_sha256()
            if sha256:
                hex_str = (
                    sha256.hex()
                    if isinstance(sha256, (bytes, bytearray))
                    else str(sha256)
                )
                if hex_str and hex_str != "0" * len(hex_str):
                    identifier = hex_str
        except Exception:
            pass

        # 2b. MD5 fallback
        if not identifier:
            try:
                md5 = idautils.GetInputFileMD5()
                if md5:
                    md5_str = (
                        md5.hex()
                        if isinstance(md5, (bytes, bytearray))
                        else str(md5)
                    )
                    if md5_str:
                        identifier = f"md5_{md5_str}"
            except Exception:
                pass

        # 2c. IDB path hash (last resort)
        if not identifier:
            try:
                idb_path = idc.get_idb_path()
                if idb_path:
                    identifier = "idb_" + hashlib.sha256(
                        idb_path.encode()
                    ).hexdigest()
            except Exception:
                pass

        if not identifier:
            identifier = "unknown_" + str(int(time.time()))

        # 3. Persist in netnode for future sessions
        try:
            nn = idaapi.netnode(_NETNODE_INDEX_ID, 0, True)
            nn.setblob(identifier.encode("utf-8"), 0, "B")
        except Exception:
            pass

        return identifier

    return _run_on_main_thread(_identify)


# ---------------------------------------------------------------------------
# Index cache
# ---------------------------------------------------------------------------

_index_cache: Dict[str, FunctionIndex] = {}


class FunctionIndexManager:
    """Singleton-style façade for loading, caching, and persisting indexes."""

    # ------------------------------------------------------------------
    # Core accessors
    # ------------------------------------------------------------------

    @staticmethod
    def get_index() -> FunctionIndex:
        """Get the index for the currently loaded binary.

        Tries (in order): in-memory cache → on-disk file → fresh empty index.
        """
        identifier = get_program_identifier()

        # 1. Cache hit
        if identifier in _index_cache:
            return _index_cache[identifier]

        # 2. Disk
        idx = FunctionIndex.load_by_identifier(identifier)
        if idx is not None:
            _index_cache[identifier] = idx
            return idx

        # 3. Fresh
        idx = FunctionIndex()
        idx.sha256 = identifier
        idx.program_name = _get_binary_name()
        _index_cache[identifier] = idx
        return idx

    @staticmethod
    def update_index(new_index: FunctionIndex, persist: bool = True) -> bool:
        """Replace the cached index and optionally persist to disk."""
        identifier = new_index.sha256 or get_program_identifier()
        new_index.sha256 = identifier
        _index_cache[identifier] = new_index
        if persist:
            return new_index.save_to_file()
        return True

    @staticmethod
    def clear_index_completely() -> bool:
        """Remove index from cache **and** delete the file on disk."""
        identifier = get_program_identifier()
        _index_cache.pop(identifier, None)
        filepath = get_index_filepath(identifier)
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
                print(f"[AETHER] Deleted index file: {filepath}")
                return True
            except OSError as e:
                print(f"[AETHER] Failed to delete index file: {e}")
                return False
        return True

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_binary_indexed() -> bool:
        """Return ``True`` if a completed index file exists for this binary."""
        identifier = get_program_identifier()
        if identifier in _index_cache:
            return _index_cache[identifier].indexed
        filepath = get_index_filepath(identifier)
        if not os.path.isfile(filepath):
            return False
        idx = FunctionIndex.load_from_file(filepath)
        return idx is not None and idx.indexed

    @staticmethod
    def can_resume_indexing() -> bool:
        """Return ``True`` if the current index is in a resumable state."""
        idx = FunctionIndexManager.get_index()
        return idx.is_resumable()

    @staticmethod
    def is_index_stale() -> bool:
        """Heuristic: has the function count changed significantly?

        Stale if the difference exceeds 50 functions or 10% of the stored total.
        """
        idx = FunctionIndexManager.get_index()
        if idx.total_function_count == 0:
            return False
        current_count = _count_all_functions()
        diff = abs(current_count - idx.total_function_count)
        return diff > 50 or diff > idx.total_function_count * 0.1

    @staticmethod
    def get_index_filepath() -> str:
        """Return the on-disk path for the current binary's index."""
        return get_index_filepath(get_program_identifier())

    @staticmethod
    def invalidate_cache() -> None:
        """Drop the in-memory cache entry for the current binary."""
        _index_cache.pop(get_program_identifier(), None)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_binary_name() -> str:
    def _inner():
        try:
            return os.path.basename(idc.get_input_file_path() or "unknown")
        except Exception:
            return "unknown"
    return _run_on_main_thread(_inner)


def _count_all_functions() -> int:
    def _inner():
        try:
            return sum(1 for _ in idautils.Functions())
        except Exception:
            return 0
    return _run_on_main_thread(_inner)
