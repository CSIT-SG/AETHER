"""
Core indexing orchestration for the AETHER function indexing feature.

Collects functions from IDA, batches them, sends pseudocode to an LLM for
classification, parses responses into :class:`FunctionEntry` objects, and
persists the result as a resumable JSON index.

All IDA API access (decompilation, function enumeration) runs on the main
thread via ``ida_kernwin.execute_sync``.  LLM calls and orchestration run
on a background thread launched by ``run_in_background``.
"""

import json
import math
import os
import re
import threading
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_segment
import idautils
import idc

from ainalyse import load_config
from ainalyse.async_manager import run_in_background
from ainalyse.ssl_helper import create_openai_client_with_custom_ca

from .dynamic_tag_manager import DynamicTagManager
from .function_index import BatchMetadata, FunctionEntry, FunctionIndex, get_index_filepath
from .function_index_manager import FunctionIndexManager, get_program_identifier
from .function_tagger import (
    IMPORTANCE_LEVELS,
    ImportanceLevel,
    drop_unknown_if_redundant,
    get_configured_tags,
    is_importance_tag,
    normalize_tag_id,
    resolve_tag,
)


# ═══════════════════════════════════════════════════════════════════════════
# Module-level constants
# ═══════════════════════════════════════════════════════════════════════════

MAX_PROMPT_CHARS = 350_000         # ~87 500 tokens — leaves room for response
DEFAULT_BATCH_SIZE = 50            # Configurable via "indexing_batch_size"
UNKNOWN_RESOLUTION_BATCH_SIZE = 40
DEFAULT_DECOMP_CHUNK_SIZE = 20
DEFAULT_HEARTBEAT_EVERY = 100
DEFAULT_DECOMP_HEARTBEAT_INTERVAL_S = 5.0
DEFAULT_STUCK_FUNCTION_THRESHOLD_S = 45
DEFAULT_SLOW_DECOMP_THRESHOLD_S = 5
DEFAULT_MAX_FUNC_SIZE_BYTES = 0x6000
DEFAULT_DECOMP_MAX_FUNC_SIZE_BYTES = 0x3000
DEFAULT_PSEUDOCODE_CACHE_ENABLED = True
DEFAULT_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC = 0
DEFAULT_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS = 0
DEFAULT_INDEXING_DEBUG_LOGS = True
DEFAULT_INDEXING_FAILED_RETRY_MAX = 5
OVERHEAD_PER_FUNC = 200
PROMPT_FRAMING = 5000
INDEX_ENTRY_TOOL_NAME = "index_function_entry"
UNKNOWN_RESOLVE_TOOL_NAME = "resolve_unknown_entry"

# Functions that are almost always compiler/libc boilerplate.
_COMMON_LIBC_NAMES: Set[str] = {
    "memcpy", "memset", "memmove", "memcmp",
    "strlen", "strcpy", "strncpy", "strcmp", "strncmp", "strcat", "strncat",
    "strchr", "strrchr", "strstr", "strtol", "strtoul", "strtod",
    "malloc", "calloc", "realloc", "free",
    "printf", "sprintf", "snprintf", "fprintf", "vprintf", "vsnprintf",
    "scanf", "sscanf", "fscanf",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fflush",
    "exit", "abort", "_exit", "atexit",
    "abs", "labs", "atoi", "atol", "atof",
    "qsort", "bsearch",
    "isdigit", "isalpha", "isalnum", "isspace", "toupper", "tolower",
    "time", "clock", "difftime", "mktime",
    "rand", "srand",
    "setjmp", "longjmp",
}

# Whitelisted names that start with '_' but should NOT be skipped.
_UNDERSCORE_WHITELIST: Set[str] = {
    "_DllMain", "_main", "_WinMain", "_wmain", "_DllEntryPoint",
    "_wWinMain", "_tmain",
}

# ═══════════════════════════════════════════════════════════════════════════
# Module-level volatile state
# ═══════════════════════════════════════════════════════════════════════════

_cancellation_requested = threading.Event()
_indexing_in_progress = threading.Lock()


def _addr_str(addr: int) -> str:
    return f"0x{addr:08X}"


def _cache_pseudocode_map(
    index: FunctionIndex,
    pseudocode_map: Dict[int, str],
    max_chars_per_func: int = DEFAULT_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC,
    max_total_chars: int = DEFAULT_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS,
) -> Tuple[int, int]:
    """Store pseudocode in the index cache with optional size limits.

    Returns (cached_count, skipped_count).
    """
    cached = 0
    skipped = 0
    total_chars = 0

    for addr, text in pseudocode_map.items():
        if not text:
            skipped += 1
            continue
        if max_chars_per_func and len(text) > max_chars_per_func:
            skipped += 1
            continue
        if max_total_chars and (total_chars + len(text)) > max_total_chars:
            skipped += 1
            continue
        addr_key = _addr_str(addr)
        if index.set_pseudocode_cache(addr_key, text):
            cached += 1
            total_chars += len(text)
        else:
            skipped += 1

    return cached, skipped


def _record_llm_failures(
    index: FunctionIndex,
    batch_functions: List[Tuple[int, str]],
    parsed_entries: List[FunctionEntry],
    batch_number: int,
) -> List[Tuple[str, str]]:
    """Record functions missing from parsed LLM output.

    Returns list of (addr, name) for missing functions.
    """
    parsed_addrs = {normalize_address(e.address).lower() for e in parsed_entries if e.address}
    missing: List[Tuple[str, str]] = []

    for addr, name in batch_functions:
        addr_str = _addr_str(addr)
        if addr_str.lower() not in parsed_addrs:
            index.add_llm_failure(addr_str, name, batch_number, "missing_from_response")
            missing.append((addr_str, name))

    return missing


def _build_target_addr_set(func_list: List[Tuple[int, str]]) -> Set[str]:
    addrs: Set[str] = set()
    for addr, _name in func_list:
        addr_key = normalize_address(_addr_str(addr)).lower()
        if addr_key:
            addrs.add(addr_key)
    return addrs


def _count_indexed_in_target(index: FunctionIndex, target_addrs: Set[str]) -> int:
    indexed_addrs = {addr.lower() for addr in index.entries_by_address.keys() if addr}
    return sum(1 for addr in target_addrs if addr in indexed_addrs)


def _cleanup_llm_failed_entries(index: FunctionIndex) -> int:
    indexed_addrs = {normalize_address(addr).lower() for addr in index.entries_by_address.keys() if addr}
    indexed_names = {name.lower() for name in index.entries_by_name.keys() if name}

    cleaned: Dict[str, dict] = {}
    removed = 0

    for addr_key, payload in index.llm_failed_entries.items():
        norm_addr = normalize_address(str(addr_key)).lower()
        name = str(payload.get("name") or "").strip()

        if norm_addr and norm_addr in indexed_addrs:
            removed += 1
            continue
        if name and name.lower() in indexed_names:
            removed += 1
            continue
        if not norm_addr:
            removed += 1
            continue

        cleaned[norm_addr] = payload

    if removed or len(cleaned) != len(index.llm_failed_entries):
        index.llm_failed_entries = cleaned
    return removed


def _build_retry_candidates(
    index: FunctionIndex,
    pseudocode_map: Dict[int, str],
) -> List[Tuple[int, str]]:
    candidates: List[Tuple[int, str]] = []

    for addr_key, payload in index.llm_failed_entries.items():
        norm_addr = normalize_address(str(addr_key))
        if not norm_addr:
            continue
        try:
            addr_int = int(norm_addr, 16)
        except Exception:
            continue
        if addr_int not in pseudocode_map:
            continue
        name = str(payload.get("name") or f"sub_{addr_int:X}").strip()
        candidates.append((addr_int, name))

    return candidates


def _retry_failed_entries(
    index: FunctionIndex,
    pseudocode_map: Dict[int, str],
    callees_map: Dict[int, List[str]],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
    config: dict,
    batch_size: int,
    entry_point_count: int,
    enable_debug_logs: bool,
    identifier: str,
    max_attempts: int,
) -> None:
    if max_attempts <= 0:
        return

    def _merge_retry_entries(batch_entries: List[FunctionEntry], tokens: int) -> None:
        for entry in batch_entries:
            index.add_entry(entry)
        if tokens:
            index.batch_metadata.batch_token_counts.append(tokens)
            index.total_tokens_used = index.batch_metadata.total_tokens()
        index.timestamp = int(time.time() * 1000)
        index.save_to_file()

    for attempt in range(1, max_attempts + 1):
        removed = _cleanup_llm_failed_entries(index)
        candidates = _build_retry_candidates(index, pseudocode_map)

        if not candidates:
            if removed:
                index.save_to_file()
            return

        filtered_pseudocode_map = {
            addr: pseudocode_map[addr]
            for addr, _name in candidates
            if addr in pseudocode_map
        }
        
        batches = split_into_batches(candidates, filtered_pseudocode_map, batch_size)
        if not batches:
            return

        prior_failed = len(index.llm_failed_entries)
        retry_total = len(candidates)
        retry_batches = len(batches)
        processed = 0
        retry_batch_base = index.batch_metadata.completed_batches + 1

        print(
            f"[AETHER] [Indexer] Retry pass {attempt}/{max_attempts}: "
            f"{retry_total} failed functions in {retry_batches} batches"
        )

        for batch_idx, batch in enumerate(batches, start=1):
            if _cancellation_requested.is_set():
                print("[AETHER] [Indexer] Retry pass cancelled by user.")
                return

            processed += len(batch)
            print(
                f"[AETHER] [Indexer] Retry {attempt}/{max_attempts} "
                f"batch {batch_idx}/{retry_batches} — {processed}/{retry_total} functions"
            )

            batch_number = retry_batch_base + batch_idx - 1

            prompt = build_classification_prompt(
                batch,
                pseudocode_map,
                callees_map,
                batch_number,
                index.batch_metadata.total_batches,
                entry_point_count,
                configured_tags,
            )

            try:
                tool_calls, tokens, response_text, message = _call_llm_with_tools(
                    prompt, config, _build_indexing_tools(), tool_choice="required"
                )
            except Exception as exc:
                error_msg = f"LLM API error during retry batch {batch_number}: {exc}"
                print(f"[AETHER] [Indexer] {error_msg}")
                index.batch_metadata.last_error = error_msg
                index.save_to_file()
                return

            if not tool_calls:
                print(f"[AETHER] [Indexer] Empty tool-call response for retry batch {batch_number} — skipping")
                index.batch_metadata.last_error = f"Empty tool-call response on retry batch {batch_number}"
                index.merge_and_persist([], batch_number, index.batch_metadata.total_batches, tokens)
                continue

            batch_entries = parse_classification_tool_calls(
                tool_calls, callees_map, configured_tags, tag_manager, index, batch_number,
            )

            missing_entries = _record_llm_failures(index, batch, batch_entries, batch_number)
            if missing_entries:
                missing_preview = ", ".join([f"{addr}({name})" for addr, name in missing_entries[:10]])
                print(
                    f"[AETHER] [Indexer] Retry batch {batch_number}: "
                    f"{len(missing_entries)} functions missing from LLM output: {missing_preview}"
                )

            index_filepath = get_index_filepath(identifier)
            _save_llm_response_debug(
                index_filepath,
                batch_number,
                len(batch),
                response_text,
                len(batch_entries),
                enable_debug=enable_debug_logs,
                tool_call_count=len(tool_calls),
                tool_calls=tool_calls,
                message=message,
            )

            _merge_retry_entries(batch_entries, tokens)
            index.batch_metadata.phase = "CLASSIFYING"

        _cleanup_llm_failed_entries(index)
        index.save_to_file()

        if len(index.llm_failed_entries) >= prior_failed:
            print("[AETHER] [Indexer] Retry pass made no progress; stopping further retries.")
            return


def _llm_logs_dir(index_filepath: str) -> str:
    """Path to LLM logs subdirectory for this index."""
    base_dir = os.path.dirname(index_filepath)
    llm_logs = os.path.join(base_dir, "llm_logs")
    return llm_logs


def _ensure_llm_logs_dir(index_filepath: str) -> str:
    """Ensure llm_logs directory exists and return its path."""
    logs_dir = _llm_logs_dir(index_filepath)
    try:
        os.makedirs(logs_dir, exist_ok=True)
    except Exception as exc:
        print(f"[AETHER] [Indexer] Failed to create llm_logs directory: {exc}")
    return logs_dir


def _response_debug_path(index_filepath: str, batch_num: int) -> str:
    """Path for LLM response debug log (in llm_logs subdirectory)."""
    logs_dir = _ensure_llm_logs_dir(index_filepath)
    filename = f"batch_{batch_num:03d}_response_debug.txt"
    return os.path.join(logs_dir, filename)


def _detect_response_format_issues(response: str) -> Dict[str, object]:
    """Analyze LLM response for format issues.
    
    Returns dict with statistics about potential problems.
    """
    issues = {
        "total_chars": len(response),
        "line_count": response.count("\n") + 1,
        "function_headers_found": len(re.findall(r"FUNCTION:\s*(.+?)\s*\[", response, re.IGNORECASE)),
        "importance_fields": len(re.findall(r"IMPORTANCE:", response, re.IGNORECASE)),
        "categories_fields": len(re.findall(r"CATEGORIES:", response, re.IGNORECASE)),
        "summary_fields": len(re.findall(r"SUMMARY:", response, re.IGNORECASE)),
        "double_newlines": response.count("\n\n"),
        "potential_issues": [],
    }
    
    # Check for missing required fields
    if issues["function_headers_found"] > 0:
        if issues["importance_fields"] == 0:
            issues["potential_issues"].append("No IMPORTANCE: fields found")
        elif issues["importance_fields"] != issues["function_headers_found"]:
            issues["potential_issues"].append(
                f"IMPORTANCE count mismatch: {issues['importance_fields']} fields vs "
                f"{issues['function_headers_found']} functions"
            )
        
        if issues["categories_fields"] == 0:
            issues["potential_issues"].append("No CATEGORIES: fields found")
        elif issues["categories_fields"] != issues["function_headers_found"]:
            issues["potential_issues"].append(
                f"CATEGORIES count mismatch: {issues['categories_fields']} fields vs "
                f"{issues['function_headers_found']} functions"
            )
        
        if issues["summary_fields"] == 0:
            issues["potential_issues"].append("No SUMMARY: fields found")
        elif issues["summary_fields"] != issues["function_headers_found"]:
            issues["potential_issues"].append(
                f"SUMMARY count mismatch: {issues['summary_fields']} fields vs "
                f"{issues['function_headers_found']} functions"
            )
    
    if issues["double_newlines"] > 0:
        issues["potential_issues"].append(f"Found {issues['double_newlines']} blank lines (may break regex)")
    
    # Sample malformed entries (first 500 chars of potentially bad entries)
    bad_samples = []
    potential_func_starts = re.finditer(r"(?:FUNCTION:|IMPORTANCE:|CATEGORIES:).{0,300}", response, re.IGNORECASE)
    for i, match in enumerate(potential_func_starts):
        if i >= 5:  # Limit to first 5 samples
            break
        bad_samples.append(match.group(0))
    
    if bad_samples:
        issues["sample_entries"] = bad_samples
    
    return issues


def _tool_calls_to_jsonable(tool_calls: Optional[List[Any]]) -> List[dict]:
    out: List[dict] = []
    for tool_call in tool_calls or []:
        if isinstance(tool_call, dict):
            out.append(tool_call)
            continue
        try:
            if hasattr(tool_call, "model_dump"):
                out.append(tool_call.model_dump())
                continue
        except Exception:
            pass
        try:
            out.append({
                "id": getattr(tool_call, "id", None),
                "type": getattr(tool_call, "type", None),
                "function": getattr(tool_call, "function", None),
            })
        except Exception:
            out.append({"raw": str(tool_call)})
    return out


def _message_to_jsonable(message: Any) -> dict:
    if message is None:
        return {}
    if isinstance(message, dict):
        return message
    try:
        if hasattr(message, "model_dump"):
            return message.model_dump()
    except Exception:
        pass
    try:
        return {
            "content": getattr(message, "content", None),
            "role": getattr(message, "role", None),
            "tool_calls": _tool_calls_to_jsonable(getattr(message, "tool_calls", None)),
        }
    except Exception:
        return {"raw": str(message)}


def _save_llm_response_debug(
    index_filepath: str,
    batch_num: int,
    batch_size: int,
    response_text: str,
    match_count: int,
    enable_debug: bool = True,
    tool_call_count: Optional[int] = None,
    tool_calls: Optional[List[Any]] = None,
    message: Optional[Any] = None,
) -> None:
    """Save LLM response and analysis to debug file.
    
    Args:
        enable_debug: If False, skip writing debug logs to reduce I/O. Can be controlled via config.
    """
    if not enable_debug:
        return
    
    debug_path = _response_debug_path(index_filepath, batch_num)
    try:
        format_analysis = _detect_response_format_issues(response_text)
        
        with open(debug_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"LLM RESPONSE DEBUG LOG — Batch {batch_num}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"STATISTICS:\n")
            f.write(f"  Functions sent to LLM: {batch_size}\n")
            f.write(f"  Expected function count: {batch_size}\n")
            f.write(f"  Function headers detected: {format_analysis['function_headers_found']}\n")
            if tool_call_count is not None:
                f.write(f"  Tool calls returned: {tool_call_count}\n")
            f.write(f"  Parsed entries: {match_count}\n")
            f.write(f"  Functions LOST: {batch_size - match_count}\n")
            f.write(f"  Loss percentage: {(batch_size - match_count) / max(1, batch_size) * 100:.1f}%\n\n")
            
            f.write(f"RESPONSE CHARACTERISTICS:\n")
            f.write(f"  Total characters: {format_analysis['total_chars']}\n")
            f.write(f"  Total lines: {format_analysis['line_count']}\n")
            f.write(f"  IMPORTANCE fields: {format_analysis['importance_fields']}\n")
            f.write(f"  CATEGORIES fields: {format_analysis['categories_fields']}\n")
            f.write(f"  SUMMARY fields: {format_analysis['summary_fields']}\n")
            f.write(f"  Double newlines (potential breaks): {format_analysis['double_newlines']}\n\n")
            
            if format_analysis["potential_issues"]:
                f.write(f"DETECTED ISSUES:\n")
                for issue in format_analysis["potential_issues"]:
                    f.write(f"  ⚠ {issue}\n")
                f.write("\n")
            
            f.write(f"ANALYSIS:\n")
            if batch_size > match_count > 0:
                f.write(f"  • Parsed {match_count} entries from tool calls\n")
                f.write(f"  • {batch_size - match_count} functions lost due to missing or invalid tool calls\n\n")
                f.write(f"  DIAGNOSIS: Parsing issue (missing/invalid tool-call arguments)\n")
            elif match_count == 0 and batch_size > 0:
                f.write(f"  • No entries parsed from tool calls\n")
                f.write(f"  • This suggests tool calls were missing or invalid\n\n")
                f.write(f"  DIAGNOSIS: Likely tool-call failure or LLM ignored instructions\n")
            elif match_count == batch_size:
                f.write(f"  • All {batch_size} functions successfully parsed\n\n")
                f.write(f"  DIAGNOSIS: No issues detected\n")
            else:
                f.write(f"  • Unexpected result state\n\n")
            
            if response_text:
                f.write("\n" + "=" * 80 + "\n")
                f.write("ASSISTANT MESSAGE TEXT (first 50KB):\n")
                f.write("=" * 80 + "\n\n")
                response_preview = response_text[:50000]
                f.write(response_preview)
                if len(response_text) > 50000:
                    f.write(f"\n\n... [TRUNCATED: {len(response_text) - 50000} more characters] ...\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("RAW MESSAGE (JSON):\n")
            f.write("=" * 80 + "\n\n")
            try:
                f.write(json.dumps(_message_to_jsonable(message), indent=2, ensure_ascii=False))
            except Exception as exc:
                f.write(f"<failed to serialize message: {exc}>")
        
        print(f"[AETHER] [Indexer] Response debug saved to: {debug_path} (Sent: {batch_size} functions)")
    except Exception as exc:
        print(f"[AETHER] [Indexer] Failed to save response debug: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Function Collection & Filtering
# ═══════════════════════════════════════════════════════════════════════════

def get_all_functions() -> List[Tuple[int, str]]:
    """Return ``[(func_addr, func_name), ...]`` for every function in the IDB."""
    results: List[Tuple[int, str]] = []
    for func_addr in idautils.Functions():
        func_name = ida_name.get_name(func_addr) or f"sub_{func_addr:x}"
        results.append((func_addr, func_name))
    return results


def is_common_library_function(name: str, func_flags: int) -> bool:
    """Return ``True`` if *name* / *func_flags* indicate a function to skip."""
    # IDA library-code flag
    if func_flags & ida_funcs.FUNC_LIB:
        return True

    # Jump stubs
    if name.startswith("j_"):
        return True

    # nullsub_ stubs
    if name.startswith("nullsub_"):
        return True

    # Common libc exact match
    if name in _COMMON_LIBC_NAMES:
        return True

    # Underscore-prefixed names (compiler internals) — unless whitelisted
    if name.startswith("_") and name not in _UNDERSCORE_WHITELIST:
        # Allow single underscore + capital (e.g. _MyFunc) as a heuristic
        if name.startswith("___") or name.startswith("__"):
            return True
        # Single underscore: skip only if it's a known libc variant
        bare = name.lstrip("_")
        if bare in _COMMON_LIBC_NAMES:
            return True

    # sub_ with tiny size (< 16 bytes is likely a stub/thunk)
    if name.startswith("sub_"):
        try:
            func = ida_funcs.get_func(int(name[4:], 16))
            if func and (func.end_ea - func.start_ea) < 16:
                return True
        except (ValueError, TypeError):
            pass

    return False


def _should_skip_for_indexing(ea: int, name: str, max_func_size_bytes: int = DEFAULT_MAX_FUNC_SIZE_BYTES) -> bool:
    """Return True for functions unlikely to provide indexing value.

    This aggressively skips import/linkage/runtime helper stubs that
    frequently cause decompile noise or wasted work on very large binaries.
    """
    func = ida_funcs.get_func(ea)
    if not func:
        return True

    if func.flags & ida_funcs.FUNC_LIB:
        return True

    if func.flags & ida_funcs.FUNC_THUNK:
        return True

    func_size = max(0, int(func.end_ea - func.start_ea))
    if func_size <= 0:
        return True
    if max_func_size_bytes > 0 and func_size > max_func_size_bytes:
        return True

    lname = (name or "").lower()
    if lname.startswith(("runtime.call", "__imp_", "j_", "thunk_", "nullsub_")):
        return True

    seg = ida_segment.getseg(ea)
    seg_name = ida_segment.get_segm_name(seg).lower() if seg else ""
    if seg_name in (".plt", "extern", "import"):
        return True

    return False


def collect_non_common_functions(max_func_size_bytes: int = DEFAULT_MAX_FUNC_SIZE_BYTES) -> List[Tuple[int, str]]:
    """Filtered list of ``(addr, name)`` excluding library / trivial stubs."""
    result: List[Tuple[int, str]] = []
    for addr, name in get_all_functions():
        if _should_skip_for_indexing(addr, name, max_func_size_bytes=max_func_size_bytes):
            continue
        func = ida_funcs.get_func(addr)
        flags = func.flags if func else 0
        if not is_common_library_function(name, flags):
            result.append((addr, name))
    return result


def generate_pseudocode_for_functions(
    func_list: List[Tuple[int, str]],
    chunk_size: int = DEFAULT_DECOMP_CHUNK_SIZE,
    max_decomp_func_size_bytes: int = DEFAULT_DECOMP_MAX_FUNC_SIZE_BYTES,
    slow_decompile_threshold_s: int = DEFAULT_SLOW_DECOMP_THRESHOLD_S,
    skip_addrs: Optional[Set[str]] = None,
    on_heavy_skip: Optional[Callable[[int, str, str], None]] = None,
    progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
    on_function_start: Optional[Callable[[int, str, int, int], None]] = None,
    on_function_result: Optional[Callable[[str, int], None]] = None,
) -> Dict[int, str]:
    """Generate Hex-Rays pseudocode for each function.

    **Must** run on the main IDA thread.  When called from a background
    thread wrap the call with ``ida_kernwin.execute_sync``.

    Returns ``{func_addr: pseudocode_str}``.  Failures are skipped with a
    warning.
    """
    result: Dict[int, str] = {}
    total = len(func_list)
    processed = 0
    decompiled = 0
    skipped = 0
    first_decompile_logged = False
    # Kept for backward compatibility; decompilation now runs one function per
    # execute_sync call so the UI can refresh after each function.
    _ = max(1, int(chunk_size or DEFAULT_DECOMP_CHUNK_SIZE))

    for index, (addr, name) in enumerate(func_list, start=1):
        if _cancellation_requested.is_set():
            print("[AETHER] [Indexer] Cancellation requested during decompilation stage.")
            break

        if on_function_start:
            on_function_start(addr, name, index, total)

        addr_str = _addr_str(addr)
        if skip_addrs and addr_str.lower() in skip_addrs:
            print(f"[AETHER] [Indexer] Skipping blacklisted decompile target: {name} at {hex(addr)}")
            skipped += 1
            processed += 1
            if on_function_result:
                on_function_result("skip", addr)
            if progress_callback:
                progress_callback(processed, total, decompiled, skipped)
            time.sleep(0.005)
            continue

        heavy_skip, reason = _should_skip_heavy_decompile_function(addr, name, max_decomp_func_size_bytes)
        if heavy_skip:
            print(f"[AETHER] [Indexer] Skipping heavy decompile target: {name} at {hex(addr)}")
            if on_heavy_skip and reason:
                on_heavy_skip(addr, name, reason)
            skipped += 1
            processed += 1
            if on_function_result:
                on_function_result("skip", addr)
            if progress_callback:
                progress_callback(processed, total, decompiled, skipped)
            time.sleep(0.005)
            continue

        decompiled_text: Optional[str] = None
        status = "skip"

        def _decompile_one() -> int:
            nonlocal decompiled_text, status
            try:
                cfunc = ida_hexrays.decompile(addr)
                if not cfunc:
                    print(f"[AETHER] [Indexer] Skipping {name} (decompile returned None)")
                    status = "skip"
                    return 1
                lines = cfunc.get_pseudocode()
                text_lines = [ida_lines.tag_remove(sline.line) for sline in lines]
                decompiled_text = "\n".join(text_lines)
                status = "ok"
            except ida_hexrays.DecompilationFailure:
                print(f"[AETHER] [Indexer] Decompilation failure for {name} at {hex(addr)}")
                status = "fail"
            except Exception as exc:
                print(f"[AETHER] [Indexer] Error decompiling {name}: {exc}")
                status = "fail"
            return 1

        decompile_started = time.monotonic()
        ida_kernwin.execute_sync(_decompile_one, ida_kernwin.MFF_READ)
        decompile_elapsed_s = time.monotonic() - decompile_started

        if not first_decompile_logged:
            first_decompile_logged = True
            print(
                f"[AETHER] [Indexer] First decompile returned in {decompile_elapsed_s:.2f}s "
                "(Hex-Rays may be restoring cache/microcode)"
            )

        if decompile_elapsed_s >= max(1, int(slow_decompile_threshold_s)):
            print(
                f"[AETHER] [Indexer] Slow decompile: {name} at {hex(addr)} "
                f"took {decompile_elapsed_s:.2f}s"
            )

        if status == "ok" and decompiled_text is not None:
            result[addr] = decompiled_text
            decompiled += 1
        else:
            skipped += 1

        processed += 1

        if on_function_result:
            on_function_result(status, addr)

        if progress_callback:
            progress_callback(processed, total, decompiled, skipped)

        # Yield so the worker can process cancellation/other events.
        time.sleep(0.005)

    return result


def _should_skip_heavy_decompile_function(
    ea: int,
    name: str,
    max_decomp_func_size_bytes: int = DEFAULT_DECOMP_MAX_FUNC_SIZE_BYTES,
) -> Tuple[bool, Optional[str]]:
    """Return (should_skip, reason) for heavy decompile targets."""
    func_size_holder: Dict[str, int] = {"size": -1}

    def _read_func_size() -> int:
        func = ida_funcs.get_func(ea)
        if not func:
            func_size_holder["size"] = -1
            return 1
        func_size_holder["size"] = max(0, int(func.end_ea - func.start_ea))
        return 1

    try:
        ida_kernwin.execute_sync(_read_func_size, ida_kernwin.MFF_READ)
    except Exception:
        # If thread marshalling fails, do not hard-fail indexing.
        return False, None

    func_size = int(func_size_holder.get("size", -1))
    if func_size <= 0:
        return True, "invalid_size"
    if max_decomp_func_size_bytes > 0 and func_size > max_decomp_func_size_bytes:
        return True, "size_limit"

    lname = (name or "").lower()
    if "crypto_" in lname and ".block" in lname:
        return True, "crypto_block"

    return False, None


def get_callees(func_addr: int) -> List[str]:
    """Return names of functions called by the function at *func_addr*."""
    callees: List[str] = []
    func = ida_funcs.get_func(func_addr)
    if not func:
        return callees
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            callee_func = ida_funcs.get_func(xref)
            if callee_func and callee_func.start_ea != func.start_ea:
                name = ida_name.get_name(callee_func.start_ea)
                if name and name not in callees:
                    callees.append(name)
    return callees


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Batching & Prompt Building
# ═══════════════════════════════════════════════════════════════════════════

def calculate_batch_count(
    pseudocode_map: Dict[int, str],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> int:
    """Calculate how many LLM batches are needed using a greedy approach.

    Respects the requested *batch_size* but will split further if a batch
    would exceed :data:`MAX_PROMPT_CHARS`.
    """
    if not pseudocode_map:
        return 0

    batch_size = max(1, min(batch_size, len(pseudocode_map)))

    batch_count = 0
    current_chars = PROMPT_FRAMING
    current_count = 0

    for pc in pseudocode_map.values():
        func_chars = len(pc) + OVERHEAD_PER_FUNC
        if current_count > 0 and (current_count >= batch_size or (current_chars + func_chars) > MAX_PROMPT_CHARS):
            batch_count += 1
            current_chars = PROMPT_FRAMING
            current_count = 0

        current_chars += func_chars
        current_count += 1

    if current_count > 0:
        batch_count += 1

    return batch_count


def split_into_batches(
    func_list: List[Tuple[int, str]],
    pseudocode_map: Dict[int, str],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> List[List[Tuple[int, str]]]:
    """Split *func_list* into batches respecting config and token budget (greedily)."""
    n_funcs = len(func_list)
    if n_funcs == 0:
        return []

    batch_size = max(1, min(batch_size, n_funcs))

    batches: List[List[Tuple[int, str]]] = []
    current_batch: List[Tuple[int, str]] = []
    current_chars = PROMPT_FRAMING
    current_count = 0

    for item in func_list:
        addr = item[0]
        pc = pseudocode_map.get(addr, "")
        func_chars = len(pc) + OVERHEAD_PER_FUNC
        
        if current_count > 0 and (current_count >= batch_size or (current_chars + func_chars) > MAX_PROMPT_CHARS):
            batches.append(current_batch)
            current_batch = []
            current_chars = PROMPT_FRAMING
            current_count = 0
            
        current_batch.append(item)
        current_chars += func_chars
        current_count += 1
        
    if current_batch:
        batches.append(current_batch)
        
    return batches


def build_classification_prompt(
    batch_functions: List[Tuple[int, str]],
    pseudocode_map: Dict[int, str],
    callees_map: Dict[int, List[str]],
    batch_number: int,
    total_batches: int,
    entry_point_count: int,
    configured_tags: Dict[str, str],
) -> str:
    """Build the full classification prompt for one batch (Section 8 template)."""
    batch_size = len(batch_functions)

    # --- Build tag list for prompt ---
    tag_lines_list = []
    for tag_id, description in configured_tags.items():
        tag_lines_list.append(f"- {tag_id}: {description}")
    tag_lines = "\n".join(tag_lines_list)

    # --- Build pseudocode section using list for efficiency ---
    pseudocode_lines = []
    for addr, name in batch_functions:
        pc = pseudocode_map.get(addr)
        if not pc:
            continue
        addr_str = f"0x{addr:08X}"
        pseudocode_lines.append(f"\n## {name} [{addr_str}]\n```c\n{pc}\n```")
    pseudocode_section = "\n".join(pseudocode_lines)

    prompt = f"""You are an expert reverse engineer analyzing a binary program.

This is BATCH {batch_number} of {total_batches} for this binary.
Analyze ONLY the {batch_size} functions shown below in this batch.

This binary has {entry_point_count} entry points.
Your task is to classify each function according to a hierarchical tagging system.

# Tagging System

## Importance Levels (assign ONE to each function):
- CRITICAL: Entry points, main loops, C2 command handlers, primary encryption/decryption, payload execution
- HIGH: Network API calls, file API with paths, registry modification, process/thread creation, crypto operations, anti-analysis, persistence setup
- MEDIUM: Data parsing/serialization, config handling, string encoding/decoding, buffer management, event dispatch, meaningful error handling
- LOW: Single-API wrappers with minimal logic, simple type conversions, basic logging, simple validation
- MINIMAL: Empty/near-empty functions, simple getters/setters, single return, compiler stubs

## Functional Categories (assign ONE OR MORE to each function):
{tag_lines}
### Dynamic Sub-Categories (LLM-Generated Tags)
You are STRONGLY ENCOURAGED to create CHILD sub-categories under EXISTING parent categories when:
- The function's purpose fits a parent category but needs more specificity
- A more specific sub-category would improve searchability for this binary
- The binary has domain-specific functionality that fits under an existing parent

CRITICAL RULES for dynamic categories:
- ALWAYS use an existing parent category as a prefix when applicable!
  - DNS operations → 'network:dns' NOT 'dns' (network is the parent)
  - Thread pools → 'synchronization:thread-pool' NOT 'thread-pool'
  - Hash tables → 'data-structures:hash-tables' NOT 'hash-tables'
  - Socket creation → 'network:socket-creation' NOT 'socket-creation'
- Use 'Parent:child-name' format with kebab-case child names
- Only create NEW parent categories when functionality truly doesn't fit ANY existing parent
- Do NOT create near-duplicates of existing categories
- NEVER use 'unknown' if you can categorize under a parent with a descriptive child
- When in doubt, use 'parent:specific-child' rather than inventing a new parent or using 'unknown'

# Functions to Classify in This Batch ({batch_size} functions)

# Pseudocode
{pseudocode_section}
# Output Format

Return ONLY tool calls. Use the tool named "{INDEX_ENTRY_TOOL_NAME}" once per function.
Do not include any plain text, markdown, or separators.

## IMPORTANCE LEVEL DECISION GUIDE (apply highest matching):
CRITICAL - Mark as CRITICAL if ANY of these apply:
  - Function is an entry point (main, DllMain, WinMain, exported function)
  - Function contains main program loop or event dispatcher
  - Function handles C2 commands or protocol parsing
  - Function performs primary encryption/decryption of payloads
  - Function executes downloaded code or payloads

HIGH - Mark as HIGH if ANY of these apply:
  - Calls network APIs (socket, connect, send, recv, WSA*, WinHTTP*, WinINet*)
  - Calls file APIs with paths (CreateFile, WriteFile, DeleteFile, fopen)
  - Modifies registry (RegSetValue, RegCreateKey)
  - Creates processes/threads (CreateProcess, CreateThread, NtCreateThreadEx)
  - Performs crypto operations (CryptEncrypt, AES, XOR with key)
  - Implements anti-analysis (IsDebuggerPresent, VM detection, timing checks)
  - Sets up persistence (services, scheduled tasks, run keys)

MEDIUM - Mark as MEDIUM if:
  - Parses or serializes data structures
  - Handles configuration data
  - Performs string encoding/decoding (Base64, hex, URL encoding)
  - Manages buffers with non-trivial logic
  - Dispatches callbacks or handles events
  - Contains meaningful error handling logic

LOW - Mark as LOW if:
  - Wraps a single API call with minimal logic
  - Performs simple type conversions
  - Basic logging or debug output
  - Simple validation checks

MINIMAL - Mark as MINIMAL if:
  - Function is empty or nearly empty
  - Simple getter/setter with no logic
  - Single return statement
  - Compiler-generated stub

## SUMMARY WRITING GUIDE (critical for search quality):
Write summaries that enable effective retrieval. Structure each summary as:
1. WHAT (verb-first): 'Establishes TCP connection to...', 'Encrypts buffer using...', 'Parses JSON config from...'
2. HOW: Key algorithm, API sequence, or data transformation used
3. CONTEXT: What triggers this, what data it operates on, where results go

Include SEARCHABLE KEYWORDS: protocol names (HTTP, DNS, SMB), algorithm names (AES, RC4, XOR),
data formats (JSON, XML, base64), Windows concepts (registry, service, mutex), attack patterns (injection, hooking).

Classification Guidelines:
- Analyze each function's pseudocode carefully
- Consider what operations the function performs
- Determine its role in the overall program behavior
- Classify by importance and functional category

Begin your classification now:
"""
    return prompt


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Response Parsing & Tag Resolution
# ═══════════════════════════════════════════════════════════════════════════

def _build_indexing_tools() -> List[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": INDEX_ENTRY_TOOL_NAME,
                "description": "Create a function index entry.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "address": {
                            "type": "string",
                            "description": "Function address in hex, e.g. 0x401000",
                        },
                        "importance": {"type": "string", "enum": sorted(IMPORTANCE_LEVELS)},
                        "categories": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "summary": {"type": "string"},
                        "key_operations": {"type": "array", "items": {"type": "string"}},
                        "key_constants": {"type": "array", "items": {"type": "string"}},
                        "called_apis": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["name", "address", "importance", "categories", "summary"],
                },
            },
        }
    ]


def _build_unknown_resolution_tools() -> List[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": UNKNOWN_RESOLVE_TOOL_NAME,
                "description": "Resolve unknown categories for a function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "categories": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                            "maxItems": 3,
                        },
                    },
                    "required": ["name", "address", "categories"],
                },
            },
        }
    ]


def normalize_address(address: Any) -> str:
    """Normalize address to 0x-prefixed, zero-padded hex string."""
    if isinstance(address, int):
        return f"0x{address:08X}"
    addr = str(address).strip()
    if not addr:
        return ""
    if addr.lower().startswith("0x"):
        addr = addr[2:]
    try:
        value = int(addr, 16)
    except Exception:
        return "0x" + addr
    return f"0x{value:08X}"


def _normalize_list_field(value: Any) -> Optional[List[str]]:
    """Ensure *value* is a list of strings. Wraps single strings in a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()]
    if not isinstance(value, list):
        # Handle cases where LLM returns a single number or other type
        return [str(value).strip()]

    items: List[str] = []
    for item in value:
        if isinstance(item, str):
            cleaned = item.strip()
        else:
            cleaned = str(item).strip()
        if cleaned:
            items.append(cleaned)
    return items


def _get_tool_call_payload(tool_call: Any) -> Tuple[Optional[str], Optional[dict], Optional[str]]:
    function_obj = None
    if isinstance(tool_call, dict):
        function_obj = tool_call.get("function")
    else:
        function_obj = getattr(tool_call, "function", None)

    if not function_obj:
        return None, None, "missing_function"

    if isinstance(function_obj, dict):
        tool_name = function_obj.get("name")
        args_raw = function_obj.get("arguments")
    else:
        tool_name = getattr(function_obj, "name", None)
        args_raw = getattr(function_obj, "arguments", None)

    if not tool_name:
        return None, None, "missing_tool_name"

    if args_raw is None:
        return tool_name, None, "missing_arguments"

    if isinstance(args_raw, dict):
        return tool_name, args_raw, None

    try:
        args = json.loads(args_raw)
    except Exception as exc:
        return tool_name, None, f"invalid_arguments_json: {exc}"

    if not isinstance(args, dict):
        return tool_name, None, "arguments_not_object"

    return tool_name, args, None


def parse_classification_tool_calls(
    tool_calls: Optional[List[Any]],
    callees_map: Dict[int, List[str]],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
    index: FunctionIndex,
    batch_number: int,
) -> List[FunctionEntry]:
    """Parse LLM tool calls into :class:`FunctionEntry` objects."""
    entries: List[FunctionEntry] = []
    tool_calls = tool_calls or []

    for tool_call in tool_calls:
        tool_name, args, error = _get_tool_call_payload(tool_call)
        if tool_name != INDEX_ENTRY_TOOL_NAME:
            if tool_name:
                print(f"[AETHER] [Indexer] Skipping tool call with unexpected name: {tool_name}")
            continue
        if error:
            print(f"[AETHER] [Indexer] Skipping tool call (bad payload): {error}")
            continue

        # Extract fields with string conversion for leniency
        address_raw = args.get("address")
        name_raw = args.get("name")
        importance_raw = args.get("importance")
        categories_raw = args.get("categories")
        summary_raw = args.get("summary")

        if address_raw is None:
            print("[AETHER] [Indexer] Skipping tool call: missing address")
            continue
        
        address = normalize_address(address_raw)
        name = str(name_raw or "").strip()
        importance_str = str(importance_raw or "").strip().upper()
        summary = str(summary_raw or "").strip()

        if not name:
            print(f"[AETHER] [Indexer] Skipping {address}: missing or empty name")
            index.add_llm_failure(address, "", batch_number, "missing_name")
            continue
        if not importance_str:
            print(f"[AETHER] [Indexer] Skipping {address} ({name}): missing or empty importance")
            index.add_llm_failure(address, name, batch_number, "missing_importance")
            continue
        if not summary:
            print(f"[AETHER] [Indexer] Skipping {address} ({name}): missing or empty summary")
            index.add_llm_failure(address, name, batch_number, "missing_summary")
            continue

        if importance_str not in IMPORTANCE_LEVELS:
            print(f"[AETHER] [Indexer] Skipping {address} ({name}): invalid importance '{importance_str}'")
            index.add_llm_failure(address, name, batch_number, "invalid_importance")
            continue

        categories_list = _normalize_list_field(categories_raw)
        if not categories_list:
            print(f"[AETHER] [Indexer] Skipping {address} ({name}): missing or empty categories")
            index.add_llm_failure(address, name, batch_number, "missing_categories")
            continue

        key_operations = _normalize_list_field(args.get("key_operations")) or []
        key_constants = _normalize_list_field(args.get("key_constants")) or []
        called_apis = _normalize_list_field(args.get("called_apis")) or []

        tags: Set[str] = {importance_str}
        for raw_tag in categories_list:
            resolved, _ = resolve_tag(raw_tag, configured_tags, tag_manager, name)
            tags.add(resolved)
        tags = drop_unknown_if_redundant(tags)

        callee_functions: List[str] = []
        try:
            addr_int = int(address, 16)
            callee_functions = callees_map.get(addr_int, [])
        except (ValueError, TypeError):
            pass

        entry = FunctionEntry(
            name=name,
            address=address,
            tags=tags,
            summary=summary,
            callee_functions=callee_functions,
            key_operations=key_operations,
            key_constants=key_constants,
            called_apis=called_apis,
        )
        entries.append(entry)

    return entries


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — Unknown Second-Pass Resolution
# ═══════════════════════════════════════════════════════════════════════════

def collect_unknown_only_entries(entries: List[FunctionEntry]) -> List[FunctionEntry]:
    """Return entries whose only non-importance tag is ``unknown``."""
    out: List[FunctionEntry] = []
    for e in entries:
        cats = e.get_functional_categories()
        if cats == {"unknown"}:
            out.append(e)
    return out


def build_unknown_resolution_prompt(
    entries: List[FunctionEntry],
    configured_tags: Dict[str, str],
) -> str:
    """Build the second-pass prompt (Section 16) for ``unknown``-only entries."""
    tag_list = "\n".join(
        f"- {tid}: {desc}"
        for tid, desc in configured_tags.items()
        if tid != "unknown"
    )

    func_blocks: List[str] = []
    for e in entries:
        block = (
            f"FUNCTION: {e.name} [{e.address}]\n"
            f"IMPORTANCE: {e.get_importance_level() or 'LOW'}\n"
            f"CALLED_APIS: {', '.join(e.called_apis) if e.called_apis else 'None'}\n"
            f"KEY_OPERATIONS: {', '.join(e.key_operations) if e.key_operations else 'None'}\n"
            f"KEY_CONSTANTS: {', '.join(e.key_constants) if e.key_constants else 'None'}\n"
            f"CALLEES: {', '.join(e.callee_functions) if e.callee_functions else 'None'}\n"
            f"SUMMARY: {e.summary}"
        )
        func_blocks.append(block)

    prompt = f"""You are improving function categorization in a reverse engineering index.
The prior classifier used category 'unknown'. Replace it with better categories.

Rules:
- DO NOT output category 'unknown'.
- Prefer using configured categories when they fit.
- You MAY invent a new category ID (short kebab-case) if none of the configured categories fit.
- Return 1 to 3 categories per function.

Configured categories:
{tag_list}

Functions to re-categorize:

{chr(10).join(func_blocks)}

Return ONLY tool calls. Use the tool named "{UNKNOWN_RESOLVE_TOOL_NAME}" once per function.
Do not include any plain text, markdown, or separators.
"""
    return prompt


def apply_unknown_resolution_tool_calls(
    tool_calls: Optional[List[Any]],
    entries: List[FunctionEntry],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
) -> int:
    """Apply unknown-resolution tool calls and replace ``unknown`` tags."""
    tool_calls = tool_calls or []
    entry_by_addr = {e.address.lower(): e for e in entries}
    entry_by_name = {e.name.lower(): e for e in entries}

    updated = 0
    for tool_call in tool_calls:
        tool_name, args, error = _get_tool_call_payload(tool_call)
        if tool_name != UNKNOWN_RESOLVE_TOOL_NAME:
            continue
        if error:
            print(f"[AETHER] [Indexer] Skipping unknown-resolve tool call (bad payload): {error}")
            continue

        addr = args.get("address")
        name = args.get("name")
        categories = _normalize_list_field(args.get("categories"))
        if not isinstance(addr, str) or not addr.strip():
            continue
        if not isinstance(name, str) or not name.strip():
            continue
        if categories is None or not categories:
            continue

        addr_key = normalize_address(addr).lower()
        name_key = name.strip().lower()
        entry = entry_by_addr.get(addr_key) or entry_by_name.get(name_key)
        if not entry:
            continue

        entry.tags.discard("unknown")
        for raw_cat in categories:
            resolved, _ = resolve_tag(raw_cat, configured_tags, tag_manager, entry.name)
            if resolved != "unknown":
                entry.tags.add(resolved)

        if not entry.get_functional_categories():
            entry.tags.add("unknown")
        else:
            updated += 1

    return updated


def resolve_unknown_entries(
    unknown_entries: List[FunctionEntry],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
    llm_call_fn: Callable[[str], Tuple[List[Any], int, str, Any]],
) -> Tuple[int, int]:
    """Orchestrate second-pass unknown resolution in batches of 40.

    *llm_call_fn* has signature ``(prompt) -> (tool_calls, tokens_used, response_text, message)``
    so this function is testable without a live LLM.

    Returns ``(entries_updated, tokens_used)``.
    """
    if not unknown_entries:
        return 0, 0

    total_updated = 0
    total_tokens = 0

    for i in range(0, len(unknown_entries), UNKNOWN_RESOLUTION_BATCH_SIZE):
        batch = unknown_entries[i : i + UNKNOWN_RESOLUTION_BATCH_SIZE]
        prompt = build_unknown_resolution_prompt(batch, configured_tags)
        try:
            tool_calls, tokens, response_text, _message = llm_call_fn(prompt)
            total_tokens += tokens
            if tool_calls:
                updated = apply_unknown_resolution_tool_calls(tool_calls, batch, configured_tags, tag_manager)
                total_updated += updated
                print(f"[AETHER] [Indexer] Unknown resolution batch: {updated}/{len(batch)} entries re-categorized")
            else:
                print("[AETHER] [Indexer] Empty tool-call response from LLM for unknown resolution batch")
        except Exception as exc:
            print(f"[AETHER] [Indexer] Error in unknown resolution batch: {exc}")

    return total_updated, total_tokens


# ═══════════════════════════════════════════════════════════════════════════
# Phase 5 — Cancellation, State Management & LLM Integration
# ═══════════════════════════════════════════════════════════════════════════

def request_cancellation() -> bool:
    """Signal cancellation of an in-progress indexing run.

    Returns ``True`` if indexing was actually in progress.
    """
    if _indexing_in_progress.locked():
        _cancellation_requested.set()
        return True
    return False


def is_indexing_in_progress() -> bool:
    """Check whether indexing is currently running."""
    return _indexing_in_progress.locked()


def _update_progress(
    batch_num: int,
    total_batches: int,
    func_count: int,
    total_funcs: int,
) -> None:
    """Log batch progress without touching the UI thread."""
    suffix = ""
    if total_funcs > 0 and func_count > total_funcs:
        suffix = " (exceeds target)"
    print(
        f"[AETHER] [Indexer] Batch {batch_num}/{total_batches} — "
        f"{func_count}/{total_funcs} functions indexed{suffix}"
    )


def _update_decompile_progress(
    processed: int,
    total: int,
    decompiled: int,
    skipped: int,
    failed: int = 0,
    current_index: Optional[int] = None,
    current_name: Optional[str] = None,
    current_ea: Optional[str] = None,
) -> None:
    """Update wait-box during decompilation stage."""
    total_w = max(1, len(str(max(total, 1))))
    minute_w = 4
    current_idx = int(current_index) if current_index is not None else 0
    est_total_min = max(1, math.ceil(max(total, 1) / 1000))
    remaining_funcs = max(0, total - processed)
    est_remaining_min = max(0, math.ceil(remaining_funcs / 1000))

    msg = (
        "Indexing: Decompiling functions\n"
        f"Progress: {processed:>{total_w}}/{total:<{total_w}}\n"
        f"Current function #: {current_idx:>{total_w}}/{total:<{total_w}}\n"
        f"Decompiled: {decompiled:>{total_w}} | Skipped: {skipped:>{total_w}} | Failed: {failed:>{total_w}}\n"
        f"ETA: ~{est_total_min:>{minute_w}} min total | ~{est_remaining_min:>{minute_w}} min remaining\n"
        "Note: popup appears because decompilation runs on IDA main thread\n"
        "Details (name/address) are tracked in index JSON; press Cancel to stop"
    )

    cancel_requested = {"value": False}

    def _ui_update():
        try:
            ida_kernwin.replace_wait_box(msg)
            try:
                cancel_requested["value"] = bool(ida_kernwin.user_cancelled())
            except Exception:
                cancel_requested["value"] = False
        except Exception:
            pass
        return 1

    ida_kernwin.execute_sync(_ui_update, ida_kernwin.MFF_FAST)
    if cancel_requested["value"]:
        _cancellation_requested.set()


def _show_wait_box(msg: str) -> None:
    """Show wait-box via the main IDA thread."""
    def _ui_show():
        try:
            ida_kernwin.show_wait_box(msg)
        except Exception:
            pass
        return 1

    ida_kernwin.execute_sync(_ui_show, ida_kernwin.MFF_FAST)


def _hide_wait_box() -> None:
    """Hide wait-box via the main IDA thread."""
    def _ui_hide():
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
        return 1

    ida_kernwin.execute_sync(_ui_hide, ida_kernwin.MFF_FAST)


def _heartbeat_index_state(
    index: FunctionIndex,
    phase: str,
    progress_percent: int,
    heartbeat_note: str,
    persist: bool = True,
) -> None:
    """Persist heartbeat/progress so users can tell indexer is alive."""
    index.indexing_state = "IN_PROGRESS"
    index.indexing_progress = max(0, min(100, int(progress_percent)))
    index.batch_metadata.phase = phase
    index.batch_metadata.last_update_time = int(time.time() * 1000)
    print(f"[AETHER] [Indexer] {phase}: {heartbeat_note}")
    if persist:
        index.save_to_file()


def _start_decompile_watchdog(
    index: FunctionIndex,
    shared_state: Dict[str, object],
    state_lock: threading.Lock,
    persist_interval_s: float,
    stuck_threshold_s: int,
) -> Tuple[threading.Event, threading.Thread]:
    """Persist decompile telemetry at a throttled interval and flag long-running functions."""
    stop_event = threading.Event()

    def _watch() -> None:
        last_flush_monotonic = 0.0
        while not stop_event.is_set():
            now_ms = int(time.time() * 1000)
            now_mono = time.monotonic()

            with state_lock:
                processed = int(shared_state.get("processed", 0))
                decompiled = int(shared_state.get("decompiled", 0))
                skipped = int(shared_state.get("skipped", 0))
                failed = int(shared_state.get("failed", 0))
                current_ea = shared_state.get("current_ea")
                current_name = shared_state.get("current_name")
                current_started_ms = int(shared_state.get("current_started_ms", 0))
                last_stuck_warn_s = int(shared_state.get("last_stuck_warn_s", 0))
                slow_decompile_functions = list(shared_state.get("slow_decompile_functions", []))
                slow_decompile_threshold_s = int(shared_state.get("slow_decompile_threshold_s", DEFAULT_SLOW_DECOMP_THRESHOLD_S))


            elapsed_s = 0
            if current_started_ms > 0:
                elapsed_s = max(0, (now_ms - current_started_ms) // 1000)

            index.batch_metadata.decompiled_count = processed
            index.batch_metadata.decompile_ok_count = decompiled
            index.batch_metadata.decompile_skip_count = skipped
            index.batch_metadata.decompile_fail_count = failed
            index.batch_metadata.current_function_ea = str(current_ea) if current_ea else None
            index.batch_metadata.current_function_name = str(current_name) if current_name else None
            index.batch_metadata.current_function_started_ms = current_started_ms
            index.batch_metadata.current_function_elapsed_s = int(elapsed_s)

            index.batch_metadata.slow_decompile_threshold_s = slow_decompile_threshold_s
            index.batch_metadata.slow_decompile_functions = slow_decompile_functions
            index.batch_metadata.last_update_time = now_ms

            if elapsed_s >= stuck_threshold_s and elapsed_s >= (last_stuck_warn_s + 15):
                print(
                    "[AETHER] [Indexer] Potential stuck decompile: "
                    f"{current_name or 'unknown'} ({current_ea or 'n/a'}) elapsed={elapsed_s}s"
                )
                with state_lock:
                    shared_state["last_stuck_warn_s"] = int(elapsed_s)

            if (now_mono - last_flush_monotonic) >= persist_interval_s:
                try:
                    index.save_to_file()
                except Exception as exc:
                    print(f"[AETHER] [Indexer] Watchdog save failed: {exc}")
                last_flush_monotonic = now_mono

            stop_event.wait(0.5)

    thread = threading.Thread(target=_watch, name="AETHER-DecompileWatchdog", daemon=True)
    thread.start()
    return stop_event, thread


def _call_llm(prompt: str, config: dict) -> Tuple[str, int]:
    """Call the LLM using the standard AETHER client-creation pattern.

    Returns ``(response_text, tokens_used)``.  Follows the same convention
    as ``call_openai_llm_annotator`` / ``call_openai_llm_gatherer`` in the
    existing codebase (``create_openai_client_with_custom_ca`` + intranet
    header injection).
    """
    api_key = config.get("OPENAI_API_KEY", "")
    base_url = config.get("OPENAI_BASE_URL", "")
    custom_ca = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert = config.get("CLIENT_CERT_PATH", "")
    client_key = config.get("CLIENT_KEY_PATH", "")
    extra_body = config.get("OPENAI_EXTRA_BODY") or None

    # Model: use indexing-specific override if set, else fall back to OPENAI_MODEL
    model = config.get("INDEXING_MODEL") or config.get("OPENAI_MODEL", "")

    client = create_openai_client_with_custom_ca(
        api_key, base_url, custom_ca, client_cert, client_key,
    )

    request_params: dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
    }

    max_tokens = config.get("INDEXING_MAX_TOKENS")
    if max_tokens:
        request_params["max_tokens"] = max_tokens

    if extra_body:
        request_params["extra_body"] = extra_body

    try:
        response = client.chat.completions.create(**request_params)
        text = response.choices[0].message.content.strip()
        tokens = getattr(response.usage, "total_tokens", 0) if response.usage else 0
        return text, tokens
    except Exception as exc:
        print(f"[AETHER] [Indexer] LLM API error: {exc}")
        raise


def _call_llm_with_tools(
    prompt: str,
    config: dict,
    tools: List[dict],
    tool_choice: str = "required",
) -> Tuple[List[Any], int, str, Any]:
    """Call the LLM and require tool calls. Returns (tool_calls, tokens, text, message)."""
    api_key = config.get("OPENAI_API_KEY", "")
    base_url = config.get("OPENAI_BASE_URL", "")
    custom_ca = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert = config.get("CLIENT_CERT_PATH", "")
    client_key = config.get("CLIENT_KEY_PATH", "")
    extra_body = config.get("OPENAI_EXTRA_BODY") or None

    model = config.get("INDEXING_MODEL") or config.get("OPENAI_MODEL", "")

    client = create_openai_client_with_custom_ca(
        api_key, base_url, custom_ca, client_cert, client_key,
    )

    request_params: dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "tools": tools,
        "tool_choice": tool_choice,
    }

    max_tokens = config.get("INDEXING_MAX_TOKENS")
    if max_tokens:
        request_params["max_tokens"] = max_tokens

    if extra_body:
        request_params["extra_body"] = extra_body

    try:
        response = client.chat.completions.create(**request_params)
        message = response.choices[0].message
        tool_calls = getattr(message, "tool_calls", None) or []
        text = (message.content or "").strip()
        tokens = getattr(response.usage, "total_tokens", 0) if response.usage else 0
        return tool_calls, tokens, text, message
    except Exception as exc:
        print(f"[AETHER] [Indexer] LLM API error: {exc}")
        raise


def _check_hexrays_available() -> bool:
    """Verify Hex-Rays is loaded.  Returns ``False`` with a warning if not."""
    try:
        available = ida_hexrays.init_hexrays_plugin()
        if not available:
            print("[AETHER] [Indexer] Hex-Rays decompiler is not available. Cannot index.")
        return bool(available)
    except Exception:
        print("[AETHER] [Indexer] Error checking Hex-Rays availability.")
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6 — Main Orchestration
# ═══════════════════════════════════════════════════════════════════════════

class FunctionIndexer:
    """Static façade exposing the three top-level operations."""

    @staticmethod
    def index_binary(
        on_success: Callable[[FunctionIndex], None],
        on_failure: Callable[[str], None],
    ) -> None:
        """Launch full binary indexing on a background thread."""
        run_in_background(_index_binary_thread, on_success, on_failure)

    @staticmethod
    def resume_indexing(
        on_success: Callable[[FunctionIndex], None],
        on_failure: Callable[[str], None],
    ) -> None:
        """Resume a partial/failed index on a background thread."""
        run_in_background(_resume_indexing_thread, on_success, on_failure)

    @staticmethod
    def request_cancellation() -> bool:
        return request_cancellation()

    @staticmethod
    def is_indexing_in_progress() -> bool:
        return is_indexing_in_progress()


# ---------------------------------------------------------------------------
# Internal orchestration — full index
# ---------------------------------------------------------------------------

def _index_binary_thread(
    on_success: Callable[[FunctionIndex], None],
    on_failure: Callable[[str], None],
) -> None:
    """Background-thread entry point for a full indexing run."""
    acquired = _indexing_in_progress.acquire(blocking=False)
    if not acquired:
        print("[AETHER] [Indexer] Indexing is already in progress.")
        on_failure("Indexing is already in progress.")
        return

    _cancellation_requested.clear()
    start_time_ms = int(time.time() * 1000)

    master_index: Optional[FunctionIndex] = None
    watchdog_stop: Optional[threading.Event] = None
    watchdog_thread: Optional[threading.Thread] = None

    try:
        # --- Step 1: Config & validation ---
        config = load_config()
        configured_tags = get_configured_tags(config)
        batch_size = int(config.get("INDEXING_BATCH_SIZE", DEFAULT_BATCH_SIZE))
        decomp_chunk_size = int(config.get("INDEXING_DECOMP_CHUNK_SIZE", DEFAULT_DECOMP_CHUNK_SIZE))
        max_func_size_bytes = int(config.get("INDEXING_MAX_FUNC_SIZE_BYTES", DEFAULT_MAX_FUNC_SIZE_BYTES))
        decomp_max_func_size_bytes = int(config.get("INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES", DEFAULT_DECOMP_MAX_FUNC_SIZE_BYTES))
        decomp_heartbeat_interval_s = float(config.get("INDEXING_DECOMP_HEARTBEAT_INTERVAL_S", DEFAULT_DECOMP_HEARTBEAT_INTERVAL_S))
        stuck_threshold_s = int(config.get("INDEXING_STUCK_FUNCTION_THRESHOLD_S", DEFAULT_STUCK_FUNCTION_THRESHOLD_S))
        slow_decomp_threshold_s = int(config.get("INDEXING_SLOW_DECOMP_THRESHOLD_S", DEFAULT_SLOW_DECOMP_THRESHOLD_S))
        enable_debug_logs = bool(config.get("DEBUG", False)) and bool(config.get("INDEXING_DEBUG_LOGS", DEFAULT_INDEXING_DEBUG_LOGS))
        failed_retry_max = int(config.get("INDEXING_FAILED_RETRY_MAX", DEFAULT_INDEXING_FAILED_RETRY_MAX))
        cache_enabled = bool(config.get("INDEXING_PSEUDOCODE_CACHE_ENABLED", DEFAULT_PSEUDOCODE_CACHE_ENABLED))
        cache_max_chars_per_func = int(config.get(
            "INDEXING_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC",
            DEFAULT_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC,
        ))
        cache_max_total_chars = int(config.get(
            "INDEXING_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS",
            DEFAULT_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS,
        ))
        tag_manager = DynamicTagManager()

        # Hex-Rays check must run on main thread
        hexrays_ok_container: dict = {"ok": False}

        def _check_hr():
            hexrays_ok_container["ok"] = _check_hexrays_available()
            return 1

        ida_kernwin.execute_sync(_check_hr, ida_kernwin.MFF_READ)
        if not hexrays_ok_container["ok"]:
            on_failure("Hex-Rays decompiler is not available.")
            return

        # --- Step 2: Collect functions ---
        func_list_container: dict = {"funcs": []}

        def _collect():
            func_list_container["funcs"] = collect_non_common_functions(max_func_size_bytes=max_func_size_bytes)
            return 1

        ida_kernwin.execute_sync(_collect, ida_kernwin.MFF_READ)
        func_list: List[Tuple[int, str]] = func_list_container["funcs"]

        if not func_list:
            on_failure("No non-library functions found in binary.")
            return

        print(f"[AETHER] [Indexer] Collected {len(func_list)} non-common functions")

        # Create index file early so progress is visible even before LLM batches.
        identifier = get_program_identifier()
        master_index = FunctionIndex()
        master_index.sha256 = identifier
        master_index.program_name = _get_binary_filename()
        master_index.total_function_count = len(func_list)
        master_index.indexing_state = "IN_PROGRESS"
        master_index.batch_metadata.start_time = start_time_ms
        _heartbeat_index_state(
            master_index,
            phase="COLLECTING_FUNCTIONS",
            progress_percent=0,
            heartbeat_note=f"Collected {len(func_list)} candidate functions",
            persist=True,
        )
        FunctionIndexManager.update_index(master_index, persist=False)

        index_filepath = get_index_filepath(identifier)
        print(f"[AETHER] [Indexer] Index file: {index_filepath}")
        # --- Step 3: Generate pseudocode (main thread) ---
        decomp_state_lock = threading.Lock()
        decomp_state: Dict[str, object] = {
            "processed": 0,
            "decompiled": 0,
            "skipped": 0,
            "failed": 0,
            "current_ea": None,
            "current_name": None,
            "current_index": 0,
            "total": len(func_list),
            "current_started_ms": 0,
            "last_stuck_warn_s": 0,
            "slow_decompile_threshold_s": max(1, slow_decomp_threshold_s),
            "slow_decompile_functions": [],
            
        }

        watchdog_stop, watchdog_thread = _start_decompile_watchdog(
            master_index,
            decomp_state,
            decomp_state_lock,
            persist_interval_s=max(1.0, decomp_heartbeat_interval_s),
            stuck_threshold_s=max(10, stuck_threshold_s),
        )

        _update_decompile_progress(
            processed=0,
            total=len(func_list),
            decompiled=0,
            skipped=0,
            failed=0,
            current_index=0,
            current_name=None,
            current_ea=None,
        )

        _heartbeat_index_state(
            master_index,
            phase="DECOMPILING",
            progress_percent=1,
            heartbeat_note=f"Starting decompilation of {len(func_list)} functions",
            persist=True,
        )

        def _on_function_start(addr: int, name: str, index: int, total: int) -> None:
            failed = 0
            decompiled = 0
            skipped = 0
            processed = 0
            with decomp_state_lock:
                decomp_state["current_ea"] = f"0x{addr:08X}"
                decomp_state["current_name"] = name
                decomp_state["current_index"] = index
                decomp_state["total"] = total
                decomp_state["current_started_ms"] = int(time.time() * 1000)
                processed = int(decomp_state.get("processed", 0))
                decompiled = int(decomp_state.get("decompiled", 0))
                skipped = int(decomp_state.get("skipped", 0))
                failed = int(decomp_state.get("failed", 0))

            _update_decompile_progress(
                processed=processed,
                total=total,
                decompiled=decompiled,
                skipped=skipped,
                failed=failed,
                current_index=index,
                current_name=name,
                current_ea=f"0x{addr:08X}",
            )

        def _on_function_result(status: str, addr: int) -> None:
            with decomp_state_lock:
                now_ms = int(time.time() * 1000)
                current_started_ms = int(decomp_state.get("current_started_ms", 0))
                elapsed_s = max(0, (now_ms - current_started_ms) // 1000) if current_started_ms > 0 else 0
                current_name = str(decomp_state.get("current_name") or "")
                current_ea = str(decomp_state.get("current_ea") or "")
                slow_threshold = int(decomp_state.get("slow_decompile_threshold_s", DEFAULT_SLOW_DECOMP_THRESHOLD_S))
                addr_key = f"0x{addr:08X}"

                if status == "ok":
                    decomp_state["decompiled"] = int(decomp_state.get("decompiled", 0)) + 1
                elif status == "skip":
                    decomp_state["skipped"] = int(decomp_state.get("skipped", 0)) + 1
                else:
                    decomp_state["failed"] = int(decomp_state.get("failed", 0)) + 1

                if elapsed_s >= max(1, slow_threshold) and current_name and current_ea:
                    slow_list = list(decomp_state.get("slow_decompile_functions", []))
                    slow_list.append({
                        "name": current_name,
                        "address": current_ea,
                        "elapsed_s": int(elapsed_s),
                        "status": status,
                    })
                    decomp_state["slow_decompile_functions"] = slow_list

                decomp_state["current_started_ms"] = 0
                decomp_state["last_stuck_warn_s"] = 0

        def _on_decomp_progress(processed: int, total: int, decompiled: int, skipped: int) -> None:
            with decomp_state_lock:
                decomp_state["processed"] = processed
                decomp_state["decompiled"] = decompiled
                decomp_state["skipped"] = skipped

        pseudocode_map: Dict[int, str] = generate_pseudocode_for_functions(
            func_list,
            chunk_size=decomp_chunk_size,
            max_decomp_func_size_bytes=decomp_max_func_size_bytes,
            slow_decompile_threshold_s=slow_decomp_threshold_s,
            skip_addrs=None,
            on_heavy_skip=lambda ea, name, reason: master_index.add_decompile_skip(_addr_str(ea), name, reason),
            progress_callback=_on_decomp_progress,
            on_function_start=_on_function_start,
            on_function_result=_on_function_result,
        )

        if cache_enabled and pseudocode_map:
            cached, skipped = _cache_pseudocode_map(
                master_index,
                pseudocode_map,
                max_chars_per_func=cache_max_chars_per_func,
                max_total_chars=cache_max_total_chars,
            )
            print(
                f"[AETHER] [Indexer] Pseudocode cache stored: {cached} entries "
                f"({skipped} skipped due to cache limits)"
            )
            master_index.save_to_file()

        if watchdog_stop is not None:
            watchdog_stop.set()
        if watchdog_thread is not None:
            watchdog_thread.join(timeout=2.0)
        _hide_wait_box()

        if _cancellation_requested.is_set():
            print("[AETHER] [Indexer] Pause requested during decompilation — discarding progress.")
            print("[AETHER] [Indexer] Note: Decompilation will restart when you resume.")
            master_index.indexing_state = "PARTIAL"
            master_index.batch_metadata.phase = "PAUSED_DECOMP"
            master_index.save_to_file()
            FunctionIndexManager.update_index(master_index, persist=False)
            on_failure("Indexing paused by user during decompilation. Resume will restart from batching phase.")
            return

        # Decompilation stage completed successfully.

        if not pseudocode_map:
            on_failure("Could not decompile any functions.")
            return

        # Filter func_list to only those with pseudocode
        func_list = [(a, n) for a, n in func_list if a in pseudocode_map]
        print(f"[AETHER] [Indexer] Generated pseudocode for {len(pseudocode_map)} functions")

        _heartbeat_index_state(
            master_index,
            phase="CLASSIFYING",
            progress_percent=40,
            heartbeat_note=f"Decompilation complete for {len(pseudocode_map)} functions",
            persist=True,
        )

        # --- Step 4: Build callees map (main thread) ---
        callees_container: dict = {"map": {}}

        def _build_callees():
            cmap: Dict[int, List[str]] = {}
            for addr, _ in func_list:
                cmap[addr] = get_callees(addr)
            callees_container["map"] = cmap
            return 1

        ida_kernwin.execute_sync(_build_callees, ida_kernwin.MFF_READ)
        callees_map: Dict[int, List[str]] = callees_container["map"]

        # --- Step 5: Setup batches & master index ---
        batches = split_into_batches(func_list, pseudocode_map, batch_size)
        total_batches = len(batches)
        target_addrs = _build_target_addr_set(func_list)

        # Count entry points for prompt context
        entry_point_count = _count_entry_points(func_list)

        master_index.total_function_count = max(master_index.total_function_count, len(func_list), master_index.size())
        master_index.batch_metadata.total_batches = total_batches
        print(f"[AETHER] [Indexer] Starting indexing: {len(func_list)} functions in {total_batches} batches (batch_size={batch_size})")

        # --- Step 6: Per-batch loop ---
        all_entries: List[FunctionEntry] = []

        for batch_idx, batch in enumerate(batches, start=1):
            indexed_in_target = _count_indexed_in_target(master_index, target_addrs)
            _update_progress(batch_idx, total_batches, indexed_in_target, len(target_addrs))

            if _cancellation_requested.is_set():
                print("[AETHER] [Indexer] Indexing paused by user — saving partial progress.")
                master_index.indexing_state = "PARTIAL"
                master_index.batch_metadata.phase = "PAUSED_INDEXING"
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure("Indexing paused by user. Partial progress saved. You can resume from where you left off.")
                return

            print(
                f"[AETHER] [Indexer] Dispatching LLM batch {batch_idx}/{total_batches} "
                f"({master_index.size()}/{len(func_list)} indexed so far) — Sending {len(batch)} functions"
            )

            prompt = build_classification_prompt(
                batch, pseudocode_map, callees_map,
                batch_idx, total_batches, entry_point_count, configured_tags,
            )

            try:
                tool_calls, tokens, response_text, message = _call_llm_with_tools(
                    prompt, config, _build_indexing_tools(), tool_choice="required"
                )
            except Exception as exc:
                error_msg = f"LLM API error on batch {batch_idx}: {exc}"
                print(f"[AETHER] [Indexer] {error_msg}")
                master_index.indexing_state = "FAILED"
                master_index.batch_metadata.last_error = error_msg
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure(error_msg)
                return

            if not tool_calls:
                print(f"[AETHER] [Indexer] Empty tool-call response for batch {batch_idx} — skipping")
                master_index.batch_metadata.last_error = f"Empty tool-call response on batch {batch_idx}"
                # Still count the batch as completed for resume purposes
                master_index.merge_and_persist([], batch_idx, total_batches, tokens)
                continue

            # --- Parse response with detailed logging ---
            print(
                f"[AETHER] [Indexer] Batch {batch_idx}/{total_batches}: "
                f"LLM returned response ({len(response_text)} chars), tool_calls={len(tool_calls)}"
            )
            
            batch_entries = parse_classification_tool_calls(
                tool_calls, callees_map, configured_tags, tag_manager, master_index, batch_idx,
            )

            missing_entries = _record_llm_failures(master_index, batch, batch_entries, batch_idx)
            if missing_entries:
                missing_preview = ", ".join([f"{addr}({name})" for addr, name in missing_entries[:10]])
                print(
                    f"[AETHER] [Indexer] Batch {batch_idx}/{total_batches}: "
                    f"{len(missing_entries)} functions missing from LLM output: {missing_preview}"
                )
            
            # Log diagnostics about parsing results
            batch_functions_count = len(batch)
            parsed_entry_count = len(batch_entries)
            loss_count = batch_functions_count - parsed_entry_count
            loss_pct = (loss_count / max(1, batch_functions_count)) * 100 if batch_functions_count > 0 else 0
            
            print(f"[AETHER] [Indexer] Batch {batch_idx}/{total_batches}: "
                  f"sent {batch_functions_count} functions → parsed {parsed_entry_count} entries "
                  f"({loss_count} lost, {loss_pct:.1f}% loss)")
            
            # Save debug response file (can be disabled via config for performance)
            index_filepath = get_index_filepath(identifier)
            _save_llm_response_debug(
                index_filepath,
                batch_idx,
                batch_functions_count,
                response_text,
                parsed_entry_count,
                enable_debug=enable_debug_logs,
                tool_call_count=len(tool_calls),
                tool_calls=tool_calls,
                message=message,
            )
            
            all_entries.extend(batch_entries)

            master_index.merge_and_persist(batch_entries, batch_idx, total_batches, tokens)
            master_index.batch_metadata.phase = "CLASSIFYING"
            # NOTE: merge_and_persist() already calls save_to_file() internally, so don't call it again
            print(f"[AETHER] [Indexer] Batch {batch_idx}/{total_batches}: saved {parsed_entry_count} entries ({tokens} tokens)")

        indexed_in_target = _count_indexed_in_target(master_index, target_addrs)
        _cleanup_llm_failed_entries(master_index)
        missing_count = len(master_index.llm_failed_entries)
        print(
            f"[AETHER] [Indexer] All {len(target_addrs)} functions have been passed to the LLM for processing"
        )
        print("[AETHER] [Indexer] Checking for any missing LLM entries")
        print(
            f"[AETHER] [Indexer] Missing entries: {missing_count}, indexed entries: {indexed_in_target}"
        )

        # --- Step 7: Second-pass unknown resolution ---
        unknown_entries = collect_unknown_only_entries(all_entries)
        if unknown_entries:
            _heartbeat_index_state(
                master_index,
                phase="RESOLVING_UNKNOWNS",
                progress_percent=95,
                heartbeat_note=f"Resolving {len(unknown_entries)} unknown-tag entries",
                persist=True,
            )
            print(f"[AETHER] [Indexer] Running second-pass on {len(unknown_entries)} 'unknown' entries...")

            def _llm_for_unknowns(prompt: str) -> Tuple[List[Any], int, str, Any]:
                return _call_llm_with_tools(
                    prompt, config, _build_unknown_resolution_tools(), tool_choice="required"
                )

            resolved_count, unknown_tokens = resolve_unknown_entries(
                unknown_entries, configured_tags, tag_manager, _llm_for_unknowns,
            )
            master_index.total_tokens_used += unknown_tokens
            print(f"[AETHER] [Indexer] Re-categorized {resolved_count} of {len(unknown_entries)} unknowns")

        if failed_retry_max > 0:
            _heartbeat_index_state(
                master_index,
                phase="RETRYING_FAILED_ENTRIES",
                progress_percent=97,
                heartbeat_note="Retrying failed LLM entries",
                persist=True,
            )
            _retry_failed_entries(
                master_index,
                pseudocode_map,
                callees_map,
                configured_tags,
                tag_manager,
                config,
                batch_size,
                entry_point_count,
                enable_debug_logs,
                identifier,
                failed_retry_max,
            )

        # --- Step 8: Finalise ---
        _heartbeat_index_state(
            master_index,
            phase="FINALIZING",
            progress_percent=99,
            heartbeat_note="Finalizing index output",
            persist=True,
        )
        tag_manager.export_to_index(master_index)
        master_index.indexed = True
        master_index.indexing_state = "COMPLETED"
        master_index.indexing_progress = 100
        master_index.batch_metadata.phase = "COMPLETED"
        master_index.batch_metadata.last_error = None
        master_index.timestamp = int(time.time() * 1000)
        master_index.save_to_file()
        FunctionIndexManager.update_index(master_index, persist=False)

        print(f"[AETHER] [Indexer] Indexing complete: {master_index.size()} functions classified, {master_index.total_tokens_used} tokens used")
        on_success(master_index)

    except Exception as exc:
        tb = traceback.format_exc()
        print(f"[AETHER] [Indexer] Unhandled exception:\n{tb}")
        if master_index is not None:
            try:
                # Best-effort save
                master_index.indexing_state = "FAILED"
                master_index.batch_metadata.phase = "FAILED"
                master_index.batch_metadata.last_error = str(exc)
                master_index.save_to_file()
            except Exception:
                pass
        on_failure(f"Unhandled error: {exc}")
    finally:
        if watchdog_stop is not None:
            watchdog_stop.set()
        if watchdog_thread is not None:
            watchdog_thread.join(timeout=2.0)
        _hide_wait_box()
        
        # Safe release: only release if we are the one who locked it
        if _indexing_in_progress.locked():
            try:
                _indexing_in_progress.release()
            except RuntimeError:
                # Already released or not owned by this thread
                pass


# ---------------------------------------------------------------------------
# Internal orchestration — resume
# ---------------------------------------------------------------------------

def _resume_indexing_thread(
    on_success: Callable[[FunctionIndex], None],
    on_failure: Callable[[str], None],
) -> None:
    """Background-thread entry point for resuming a partial index."""
    acquired = _indexing_in_progress.acquire(blocking=False)
    if not acquired:
        print("[AETHER] [Indexer] Indexing is already in progress.")
        on_failure("Indexing is already in progress.")
        return

    _cancellation_requested.clear()
    watchdog_stop: Optional[threading.Event] = None
    watchdog_thread: Optional[threading.Thread] = None

    try:
        # --- Load existing index ---
        master_index = FunctionIndexManager.get_index()
        if not master_index.is_resumable():
            on_failure("Index is not in a resumable state.")
            return

        config = load_config()
        configured_tags = get_configured_tags(config)
        batch_size = int(config.get("INDEXING_BATCH_SIZE", DEFAULT_BATCH_SIZE))
        decomp_chunk_size = int(config.get("INDEXING_DECOMP_CHUNK_SIZE", DEFAULT_DECOMP_CHUNK_SIZE))
        max_func_size_bytes = int(config.get("INDEXING_MAX_FUNC_SIZE_BYTES", DEFAULT_MAX_FUNC_SIZE_BYTES))
        decomp_max_func_size_bytes = int(config.get("INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES", DEFAULT_DECOMP_MAX_FUNC_SIZE_BYTES))
        decomp_heartbeat_interval_s = float(config.get("INDEXING_DECOMP_HEARTBEAT_INTERVAL_S", DEFAULT_DECOMP_HEARTBEAT_INTERVAL_S))
        stuck_threshold_s = int(config.get("INDEXING_STUCK_FUNCTION_THRESHOLD_S", DEFAULT_STUCK_FUNCTION_THRESHOLD_S))
        slow_decomp_threshold_s = int(config.get("INDEXING_SLOW_DECOMP_THRESHOLD_S", DEFAULT_SLOW_DECOMP_THRESHOLD_S))
        enable_debug_logs = bool(config.get("DEBUG", False)) and bool(config.get("INDEXING_DEBUG_LOGS", DEFAULT_INDEXING_DEBUG_LOGS))
        failed_retry_max = int(config.get("INDEXING_FAILED_RETRY_MAX", DEFAULT_INDEXING_FAILED_RETRY_MAX))
        cache_enabled = bool(config.get("INDEXING_PSEUDOCODE_CACHE_ENABLED", DEFAULT_PSEUDOCODE_CACHE_ENABLED))
        cache_max_chars_per_func = int(config.get(
            "INDEXING_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC",
            DEFAULT_PSEUDOCODE_CACHE_MAX_CHARS_PER_FUNC,
        ))
        cache_max_total_chars = int(config.get(
            "INDEXING_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS",
            DEFAULT_PSEUDOCODE_CACHE_MAX_TOTAL_CHARS,
        ))
        tag_manager = DynamicTagManager()
        tag_manager.initialize_from_index(master_index)

        resume_point = master_index.get_resume_point()
        already_indexed = master_index.get_indexed_addresses()

        identifier = master_index.sha256 or get_program_identifier()
        index_filepath = get_index_filepath(identifier)
        print(f"[AETHER] [Indexer] Index file: {index_filepath}")
        print(f"[AETHER] [Indexer] Resuming from batch {resume_point}, {len(already_indexed)} functions already indexed")

        # Hex-Rays check
        hexrays_ok_container: dict = {"ok": False}

        def _check_hr():
            hexrays_ok_container["ok"] = _check_hexrays_available()
            return 1

        ida_kernwin.execute_sync(_check_hr, ida_kernwin.MFF_READ)
        if not hexrays_ok_container["ok"]:
            on_failure("Hex-Rays decompiler is not available.")
            return

        # Collect all non-common functions
        func_list_container: dict = {"funcs": []}

        def _collect():
            func_list_container["funcs"] = collect_non_common_functions(max_func_size_bytes=max_func_size_bytes)
            return 1

        ida_kernwin.execute_sync(_collect, ida_kernwin.MFF_READ)
        all_funcs: List[Tuple[int, str]] = func_list_container["funcs"]

        indexed_lower = {addr.lower() for addr in already_indexed}
        blacklist = set(master_index.decompile_blacklist.keys())
        pending_funcs = [
            (a, n) for a, n in all_funcs
            if _addr_str(a).lower() not in indexed_lower
            and _addr_str(a).lower() not in blacklist
        ]

        if not pending_funcs:
            print("[AETHER] [Indexer] All functions already indexed.")
            master_index.indexed = True
            master_index.indexing_state = "COMPLETED"
            master_index.indexing_progress = 100
            master_index.total_function_count = max(master_index.total_function_count, len(all_funcs), master_index.size())
            master_index.batch_metadata.phase = "COMPLETED"
            master_index.save_to_file()
            FunctionIndexManager.update_index(master_index, persist=False)
            on_success(master_index)
            return

        pseudocode_map: Dict[int, str] = {}
        if cache_enabled and master_index.pseudocode_cache:
            for addr, _ in pending_funcs:
                cached = master_index.get_pseudocode_cache(_addr_str(addr))
                if cached:
                    pseudocode_map[addr] = cached

        cached_count = len(pseudocode_map)
        remaining_funcs = [(a, n) for a, n in pending_funcs if a not in pseudocode_map]
        if cached_count:
            print(
                f"[AETHER] [Indexer] Resume pseudocode cache hit: {cached_count} functions "
                f"({len(remaining_funcs)} remaining to decompile)"
            )

        if remaining_funcs:
            print("[AETHER] [Indexer] Resuming decompilation for uncached functions...")

            _heartbeat_index_state(
                master_index,
                phase="DECOMPILING",
                progress_percent=1,
                heartbeat_note=f"Resuming decompilation of {len(remaining_funcs)} functions",
                persist=True,
            )

            # Generate pseudocode for remaining functions
            decomp_state_lock = threading.Lock()
            decomp_state: Dict[str, object] = {
                "processed": 0,
                "decompiled": 0,
                "skipped": 0,
                "failed": 0,
                "current_ea": None,
                "current_name": None,
                "current_index": 0,
                "total": len(remaining_funcs),
                "current_started_ms": 0,
                "last_stuck_warn_s": 0,
                "slow_decompile_threshold_s": max(1, slow_decomp_threshold_s),
                "slow_decompile_functions": [],
                
            }

            watchdog_stop, watchdog_thread = _start_decompile_watchdog(
                master_index,
                decomp_state,
                decomp_state_lock,
                persist_interval_s=max(1.0, decomp_heartbeat_interval_s),
                stuck_threshold_s=max(10, stuck_threshold_s),
            )

            _update_decompile_progress(
                processed=0,
                total=len(remaining_funcs),
                decompiled=0,
                skipped=0,
                failed=0,
                current_index=0,
                current_name=None,
                current_ea=None,
            )

            def _on_function_start(addr: int, name: str, index: int, total: int) -> None:
                failed = 0
                decompiled = 0
                skipped = 0
                processed = 0
                with decomp_state_lock:
                    decomp_state["current_ea"] = f"0x{addr:08X}"
                    decomp_state["current_name"] = name
                    decomp_state["current_index"] = index
                    decomp_state["total"] = total
                    decomp_state["current_started_ms"] = int(time.time() * 1000)
                    processed = int(decomp_state.get("processed", 0))
                    decompiled = int(decomp_state.get("decompiled", 0))
                    skipped = int(decomp_state.get("skipped", 0))
                    failed = int(decomp_state.get("failed", 0))

                _update_decompile_progress(
                    processed=processed,
                    total=total,
                    decompiled=decompiled,
                    skipped=skipped,
                    failed=failed,
                    current_index=index,
                    current_name=name,
                    current_ea=f"0x{addr:08X}",
                )

            def _on_function_result(status: str, addr: int) -> None:
                with decomp_state_lock:
                    now_ms = int(time.time() * 1000)
                    current_started_ms = int(decomp_state.get("current_started_ms", 0))
                    elapsed_s = max(0, (now_ms - current_started_ms) // 1000) if current_started_ms > 0 else 0
                    current_name = str(decomp_state.get("current_name") or "")
                    current_ea = str(decomp_state.get("current_ea") or "")
                    slow_threshold = int(decomp_state.get("slow_decompile_threshold_s", DEFAULT_SLOW_DECOMP_THRESHOLD_S))

                    if status == "ok":
                        decomp_state["decompiled"] = int(decomp_state.get("decompiled", 0)) + 1
                    elif status == "skip":
                        decomp_state["skipped"] = int(decomp_state.get("skipped", 0)) + 1
                    else:
                        decomp_state["failed"] = int(decomp_state.get("failed", 0)) + 1

                    if elapsed_s >= max(1, slow_threshold) and current_name and current_ea:
                        slow_list = list(decomp_state.get("slow_decompile_functions", []))
                        slow_list.append({
                            "name": current_name,
                            "address": current_ea,
                            "elapsed_s": int(elapsed_s),
                            "status": status,
                        })
                        decomp_state["slow_decompile_functions"] = slow_list

                    decomp_state["current_started_ms"] = 0
                    decomp_state["last_stuck_warn_s"] = 0

            def _on_decomp_progress(processed: int, total: int, decompiled: int, skipped: int) -> None:
                with decomp_state_lock:
                    decomp_state["processed"] = processed
                    decomp_state["decompiled"] = decompiled
                    decomp_state["skipped"] = skipped

            decompiled_map = generate_pseudocode_for_functions(
                remaining_funcs,
                chunk_size=decomp_chunk_size,
                max_decomp_func_size_bytes=decomp_max_func_size_bytes,
                slow_decompile_threshold_s=slow_decomp_threshold_s,
                skip_addrs=blacklist,
                on_heavy_skip=lambda ea, name, reason: master_index.add_decompile_skip(_addr_str(ea), name, reason),
                progress_callback=_on_decomp_progress,
                on_function_start=_on_function_start,
                on_function_result=_on_function_result,
            )

            pseudocode_map.update(decompiled_map)

            if cache_enabled and decompiled_map:
                cached, skipped = _cache_pseudocode_map(
                    master_index,
                    decompiled_map,
                    max_chars_per_func=cache_max_chars_per_func,
                    max_total_chars=cache_max_total_chars,
                )
                print(
                    f"[AETHER] [Indexer] Pseudocode cache stored: {cached} entries "
                    f"({skipped} skipped due to cache limits)"
                )
                master_index.save_to_file()

            if watchdog_stop is not None:
                watchdog_stop.set()
            if watchdog_thread is not None:
                watchdog_thread.join(timeout=2.0)
            _hide_wait_box()

        # Decompilation complete, continue with batching

        # Filter func_list to only those with pseudocode
        func_list = [(a, n) for a, n in pending_funcs if a in pseudocode_map]
        if not func_list:
            print("[AETHER] [Indexer] No remaining functions could be decompiled.")
            master_index.indexing_state = "PARTIAL"
            master_index.batch_metadata.phase = "FAILED"
            master_index.batch_metadata.last_error = "No remaining functions could be decompiled."
            master_index.total_function_count = max(master_index.total_function_count, len(all_funcs), master_index.size())
            master_index.save_to_file()
            FunctionIndexManager.update_index(master_index, persist=False)
            on_failure("No remaining functions could be decompiled.")
            return

        _heartbeat_index_state(
            master_index,
            phase="CLASSIFYING",
            progress_percent=max(master_index.indexing_progress, 40),
            heartbeat_note=f"Resume decompilation complete for {len(func_list)} functions",
            persist=True,
        )

        # Callees
        callees_container: dict = {"map": {}}

        def _build_callees():
            cmap: Dict[int, List[str]] = {}
            for addr, _ in func_list:
                cmap[addr] = get_callees(addr)
            callees_container["map"] = cmap
            return 1

        ida_kernwin.execute_sync(_build_callees, ida_kernwin.MFF_READ)
        callees_map: Dict[int, List[str]] = callees_container["map"]

        # Re-batch
        batches = split_into_batches(func_list, pseudocode_map, batch_size)
        new_total_batches = master_index.batch_metadata.completed_batches + len(batches)
        master_index.batch_metadata.total_batches = new_total_batches
        master_index.indexing_state = "IN_PROGRESS"
        entry_point_count = _count_entry_points(all_funcs)
        target_addrs = _build_target_addr_set(all_funcs)

        total_funcs_target = master_index.total_function_count or len(all_funcs)

        # Check for pause request after all unpausable phases (decompilation, callees, batching) complete
        if _cancellation_requested.is_set():
            print("[AETHER] [Indexer] Pause requested; all setup complete. Pausing before batching.")
            master_index.indexing_state = "PARTIAL"
            master_index.batch_metadata.phase = "PAUSED_DECOMP"
            master_index.save_to_file()
            FunctionIndexManager.update_index(master_index, persist=False)
            on_failure("Indexing paused by user before batching. You can resume and continue from the first batch.")
            return

        all_entries: List[FunctionEntry] = []

        for batch in batches:
            batch_number = master_index.batch_metadata.completed_batches + 1

            indexed_in_target = _count_indexed_in_target(master_index, target_addrs)
            _update_progress(batch_number, new_total_batches, indexed_in_target, total_funcs_target)

            if _cancellation_requested.is_set():
                print("[AETHER] [Indexer] Pause requested during resume batching.")
                master_index.indexing_state = "PARTIAL"
                master_index.batch_metadata.phase = "PAUSED_INDEXING"
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure("Indexing paused by user. Progress saved.")
                return

            print(
                f"[AETHER] [Indexer] Dispatching resume LLM batch {batch_number}/{new_total_batches} "
                f"({master_index.size()}/{total_funcs_target} indexed so far) — Sending {len(batch)} functions"
            )

            prompt = build_classification_prompt(
                batch, pseudocode_map, callees_map,
                batch_number, new_total_batches, entry_point_count, configured_tags,
            )

            try:
                tool_calls, tokens, response_text, message = _call_llm_with_tools(
                    prompt, config, _build_indexing_tools(), tool_choice="required"
                )
            except Exception as exc:
                error_msg = f"LLM API error on batch {batch_number}: {exc}"
                print(f"[AETHER] [Indexer] {error_msg}")
                master_index.indexing_state = "FAILED"
                master_index.batch_metadata.last_error = error_msg
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure(error_msg)
                return

            if not tool_calls:
                print(f"[AETHER] [Indexer] Empty tool-call response for batch {batch_number} — skipping")
                master_index.batch_metadata.last_error = f"Empty tool-call response on batch {batch_number}"
                master_index.merge_and_persist([], batch_number, new_total_batches, tokens)
                continue

            # --- Parse response with detailed logging ---
            print(
                f"[AETHER] [Indexer] Resume batch {batch_number}/{new_total_batches}: "
                f"LLM returned response ({len(response_text)} chars), tool_calls={len(tool_calls)}"
            )
            
            batch_entries = parse_classification_tool_calls(
                tool_calls, callees_map, configured_tags, tag_manager, master_index, batch_number,
            )

            missing_entries = _record_llm_failures(master_index, batch, batch_entries, batch_number)
            if missing_entries:
                missing_preview = ", ".join([f"{addr}({name})" for addr, name in missing_entries[:10]])
                print(
                    f"[AETHER] [Indexer] Resume batch {batch_number}/{new_total_batches}: "
                    f"{len(missing_entries)} functions missing from LLM output: {missing_preview}"
                )
            
            # Log diagnostics about parsing results
            batch_functions_count = len(batch)
            parsed_entry_count = len(batch_entries)
            loss_count = batch_functions_count - parsed_entry_count
            loss_pct = (loss_count / max(1, batch_functions_count)) * 100 if batch_functions_count > 0 else 0
            
            print(f"[AETHER] [Indexer] Resume batch {batch_number}/{new_total_batches}: "
                  f"sent {batch_functions_count} functions → parsed {parsed_entry_count} entries "
                  f"({loss_count} lost, {loss_pct:.1f}% loss)")
            
            # Save debug response file
            index_filepath = get_index_filepath(identifier)
            _save_llm_response_debug(
                index_filepath,
                batch_number,
                batch_functions_count,
                response_text,
                parsed_entry_count,
                tool_call_count=len(tool_calls),
                tool_calls=tool_calls,
                message=message,
            )
            
            all_entries.extend(batch_entries)
            master_index.merge_and_persist(batch_entries, batch_number, new_total_batches, tokens)
            master_index.batch_metadata.phase = "CLASSIFYING"
            print(f"[AETHER] [Indexer] Resume batch {batch_number}/{new_total_batches}: saved {parsed_entry_count} entries ({tokens} tokens)")

        indexed_in_target = _count_indexed_in_target(master_index, target_addrs)
        _cleanup_llm_failed_entries(master_index)
        missing_count = len(master_index.llm_failed_entries)
        print(
            f"[AETHER] [Indexer] All {total_funcs_target} functions have been passed to the LLM for processing"
        )
        print("[AETHER] [Indexer] Checking for any missing LLM entries")
        print(
            f"[AETHER] [Indexer] Missing entries: {missing_count}, indexed entries: {indexed_in_target}"
        )

        # Second-pass unknown resolution
        unknown_entries = collect_unknown_only_entries(all_entries)
        if unknown_entries:
            _heartbeat_index_state(
                master_index,
                phase="RESOLVING_UNKNOWNS",
                progress_percent=95,
                heartbeat_note=f"Resolving {len(unknown_entries)} unknown-tag entries",
                persist=True,
            )
            print(f"[AETHER] [Indexer] Running second-pass on {len(unknown_entries)} unknowns...")

            def _llm_fn(prompt: str) -> Tuple[List[Any], int, str, Any]:
                return _call_llm_with_tools(
                    prompt, config, _build_unknown_resolution_tools(), tool_choice="required"
                )

            resolved, unk_tokens = resolve_unknown_entries(
                unknown_entries, configured_tags, tag_manager, _llm_fn,
            )
            master_index.total_tokens_used += unk_tokens

        if failed_retry_max > 0:
            _heartbeat_index_state(
                master_index,
                phase="RETRYING_FAILED_ENTRIES",
                progress_percent=97,
                heartbeat_note="Retrying failed LLM entries",
                persist=True,
            )
            _retry_failed_entries(
                master_index,
                pseudocode_map,
                callees_map,
                configured_tags,
                tag_manager,
                config,
                batch_size,
                entry_point_count,
                enable_debug_logs,
                identifier,
                failed_retry_max,
            )

        # Finalise
        tag_manager.export_to_index(master_index)
        master_index.indexed = True
        master_index.indexing_state = "COMPLETED"
        master_index.indexing_progress = 100
        master_index.total_function_count = max(master_index.total_function_count, len(all_funcs), master_index.size())
        master_index.batch_metadata.phase = "COMPLETED"
        master_index.batch_metadata.last_error = None
        master_index.timestamp = int(time.time() * 1000)
        master_index.save_to_file()
        FunctionIndexManager.update_index(master_index, persist=False)

        print(f"[AETHER] [Indexer] Resume complete: {master_index.size()} functions total")
        on_success(master_index)

    except Exception as exc:
        tb = traceback.format_exc()
        print(f"[AETHER] [Indexer] Unhandled exception during resume:\n{tb}")
        try:
            master_index.indexing_state = "FAILED"
            master_index.batch_metadata.last_error = str(exc)
            master_index.save_to_file()
        except Exception:
            pass
        on_failure(f"Unhandled error: {exc}")
    finally:
        if watchdog_stop is not None:
            watchdog_stop.set()
        if watchdog_thread is not None:
            watchdog_thread.join(timeout=2.0)
        _hide_wait_box()
        
        # Safe release: only release if we are the one who locked it
        if _indexing_in_progress.locked():
            try:
                _indexing_in_progress.release()
            except RuntimeError:
                # Already released or not owned by this thread
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_binary_filename() -> str:
    """Return the base filename of the loaded binary."""
    try:
        return os.path.basename(idc.get_input_file_path() or "unknown")
    except Exception:
        return "unknown"


def _count_entry_points(func_list: List[Tuple[int, str]]) -> int:
    """Heuristic count of entry points for prompt context."""
    ep_names = {"main", "_main", "WinMain", "_WinMain", "wmain", "_wmain",
                "wWinMain", "_wWinMain", "DllMain", "_DllMain", "DllEntryPoint",
                "_DllEntryPoint", "start", "_start", "entry"}
    return sum(1 for _, n in func_list if n in ep_names)
