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
from typing import Callable, Dict, List, Optional, Set, Tuple

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
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


def collect_non_common_functions() -> List[Tuple[int, str]]:
    """Filtered list of ``(addr, name)`` excluding library / trivial stubs."""
    result: List[Tuple[int, str]] = []
    for addr, name in get_all_functions():
        func = ida_funcs.get_func(addr)
        flags = func.flags if func else 0
        if not is_common_library_function(name, flags):
            result.append((addr, name))
    return result


def generate_pseudocode_for_functions(
    func_list: List[Tuple[int, str]],
) -> Dict[int, str]:
    """Generate Hex-Rays pseudocode for each function.

    **Must** run on the main IDA thread.  When called from a background
    thread wrap the call with ``ida_kernwin.execute_sync``.

    Returns ``{func_addr: pseudocode_str}``.  Failures are skipped with a
    warning.
    """
    result: Dict[int, str] = {}

    for addr, name in func_list:
        try:
            cfunc = ida_hexrays.decompile(addr)
            if not cfunc:
                print(f"[AETHER] [Indexer] Skipping {name} (decompile returned None)")
                continue
            lines = cfunc.get_pseudocode()
            text_lines = [ida_lines.tag_remove(sline.line) for sline in lines]
            pseudocode = "\n".join(text_lines)
            result[addr] = pseudocode
        except ida_hexrays.DecompilationFailure:
            print(f"[AETHER] [Indexer] Decompilation failure for {name} at {hex(addr)}")
        except Exception as exc:
            print(f"[AETHER] [Indexer] Error decompiling {name}: {exc}")

    return result


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
    """Calculate how many LLM batches are needed.

    Respects the requested *batch_size* but will split further if a batch
    would exceed :data:`MAX_PROMPT_CHARS`.
    """
    n_funcs = len(pseudocode_map)
    if n_funcs == 0:
        return 0

    batch_size = max(1, min(batch_size, n_funcs))

    total_chars = sum(len(pc) for pc in pseudocode_map.values())
    overhead_per_func = 200
    prompt_framing = 5000
    total_estimated = total_chars + (n_funcs * overhead_per_func) + prompt_framing

    # Everything fits in one batch?
    if total_estimated < MAX_PROMPT_CHARS and n_funcs <= batch_size:
        return 1

    batches_by_count = math.ceil(n_funcs / batch_size)

    avg_pc_size = total_chars // max(n_funcs, 1)
    chars_per_func = avg_pc_size + overhead_per_func
    max_funcs_by_tokens = max(1, (MAX_PROMPT_CHARS - prompt_framing) // chars_per_func)
    batches_by_tokens = math.ceil(n_funcs / max_funcs_by_tokens)

    return max(batches_by_count, batches_by_tokens)


def split_into_batches(
    func_list: List[Tuple[int, str]],
    pseudocode_map: Dict[int, str],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> List[List[Tuple[int, str]]]:
    """Split *func_list* into batches respecting config and token budget."""
    n_funcs = len(func_list)
    if n_funcs == 0:
        return []

    num_batches = calculate_batch_count(pseudocode_map, batch_size)
    effective_size = max(1, math.ceil(n_funcs / max(num_batches, 1)))

    batches: List[List[Tuple[int, str]]] = []
    for i in range(0, n_funcs, effective_size):
        batches.append(func_list[i : i + effective_size])
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
    tag_lines = ""
    for tag_id, description in configured_tags.items():
        if tag_id == "unknown":
            tag_lines += f"- {tag_id}: {description}\n"
        else:
            tag_lines += f"- {tag_id}: {description}\n"

    # --- Build pseudocode section ---
    pseudocode_section = ""
    for addr, name in batch_functions:
        pc = pseudocode_map.get(addr)
        if not pc:
            continue
        addr_str = f"0x{addr:08X}"
        pseudocode_section += f"\n## {name} [{addr_str}]\n```c\n{pc}\n```\n"

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

For EACH function shown above with pseudocode, output a classification in this exact format:

FUNCTION: <function_name> [<address>]
IMPORTANCE: <importance_level>
CATEGORIES: <category1>[:<sub_category>], ... (Use 'Parent:Child' for sub-tags)
KEY_OPERATIONS: <list key operations like: XOR, memcpy, socket, fopen, RegSetValue, etc.>
KEY_CONSTANTS: <list notable constants, magic bytes, XOR keys, buffer sizes, e.g.: 0xDEADBEEF, "Mozilla/5.0", 4096>
CALLED_APIS: <list external APIs called, e.g.: CreateFileA, send, malloc>
SUMMARY: <2-3 sentence description following the structure below>
---

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

_FUNCTION_PATTERN = re.compile(
    r"FUNCTION:\s*(.+?)\s*\[([^\]]+)\]\s*\n"
    r"IMPORTANCE:\s*(.+?)\s*\n"
    r"CATEGORIES:\s*(.+?)\s*\n"
    r"(?:KEY_OPERATIONS:\s*(.*?)\s*\n)?"
    r"(?:KEY_CONSTANTS:\s*(.*?)\s*\n)?"
    r"(?:CALLED_APIS:\s*(.*?)\s*\n)?"
    r"SUMMARY:\s*(.+?)\s*(?:\n|$)",
    re.IGNORECASE | re.MULTILINE,
)


def normalize_address(address: str) -> str:
    """Ensure ``0x`` prefix on an address string."""
    addr = address.strip()
    if not addr.lower().startswith("0x"):
        addr = "0x" + addr
    return addr


def parse_comma_separated(s: Optional[str]) -> List[str]:
    """Split by comma, strip whitespace, filter empty / ``none`` / ``n/a``."""
    if not s:
        return []
    ignore = {"", "none", "n/a", "n\\a", "na", "-"}
    return [
        item.strip()
        for item in s.split(",")
        if item.strip().lower() not in ignore
    ]


def parse_classification_response(
    response: str,
    callees_map: Dict[int, List[str]],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
) -> List[FunctionEntry]:
    """Parse a structured LLM classification response into entries.

    Uses the regex from Section 9 of the spec.  Each match is normalised,
    tag-resolved, and turned into a :class:`FunctionEntry`.
    """
    entries: List[FunctionEntry] = []

    for m in _FUNCTION_PATTERN.finditer(response):
        name = m.group(1).strip()
        address = normalize_address(m.group(2))
        importance_raw = m.group(3).strip().upper()
        categories_str = m.group(4)
        key_ops_str = m.group(5)
        key_consts_str = m.group(6)
        called_apis_str = m.group(7)
        summary = m.group(8).strip()

        # Validate importance — default to LOW if unrecognised
        if importance_raw not in IMPORTANCE_LEVELS:
            importance_raw = "LOW"

        # Resolve category tags
        tags: Set[str] = {importance_raw}
        for raw_tag in parse_comma_separated(categories_str):
            resolved, _ = resolve_tag(raw_tag, configured_tags, tag_manager, name)
            tags.add(resolved)

        # Drop 'unknown' if other real categories exist
        tags = drop_unknown_if_redundant(tags)

        # Parse list fields
        key_operations = parse_comma_separated(key_ops_str)
        key_constants = parse_comma_separated(key_consts_str)
        called_apis = parse_comma_separated(called_apis_str)

        # Attach callee functions from the pre-built map
        # Try to find the address as an int to look up callees
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

Respond with JSON only:
{{
  "functions": [
    {{"name": "...", "address": "0x...", "categories": ["cat1", "cat2"]}}
  ]
}}
"""
    return prompt


def apply_unknown_resolution(
    response_json: str,
    entries: List[FunctionEntry],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
) -> int:
    """Parse the second-pass JSON and replace ``unknown`` tags.

    Returns the number of entries updated.
    """
    # Extract JSON from response (may be wrapped in markdown fences)
    json_str = response_json.strip()
    json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", json_str, re.DOTALL)
    if json_match:
        json_str = json_match.group(1).strip()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        print(f"[AETHER] [Indexer] Failed to parse unknown-resolution JSON: {exc}")
        return 0

    func_list = data.get("functions", [])
    # Build lookup by address for quick matching
    entry_by_addr = {e.address.lower(): e for e in entries}
    entry_by_name = {e.name.lower(): e for e in entries}

    updated = 0
    for item in func_list:
        addr = normalize_address(item.get("address", "")).lower()
        name = (item.get("name") or "").lower()
        new_cats = item.get("categories", [])
        if not new_cats:
            continue

        entry = entry_by_addr.get(addr) or entry_by_name.get(name)
        if not entry:
            continue

        # Remove unknown, add new resolved categories
        entry.tags.discard("unknown")
        for raw_cat in new_cats:
            resolved, _ = resolve_tag(raw_cat, configured_tags, tag_manager, entry.name)
            if resolved != "unknown":
                entry.tags.add(resolved)

        # Guarantee at least one non-importance tag
        if not entry.get_functional_categories():
            entry.tags.add("unknown")
        else:
            updated += 1

    return updated


def resolve_unknown_entries(
    unknown_entries: List[FunctionEntry],
    configured_tags: Dict[str, str],
    tag_manager: DynamicTagManager,
    llm_call_fn: Callable[[str], Tuple[str, int]],
) -> Tuple[int, int]:
    """Orchestrate second-pass unknown resolution in batches of 40.

    *llm_call_fn* has signature ``(prompt) -> (response_text, tokens_used)``
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
            response_text, tokens = llm_call_fn(prompt)
            total_tokens += tokens
            if response_text:
                updated = apply_unknown_resolution(response_text, batch, configured_tags, tag_manager)
                total_updated += updated
                print(f"[AETHER] [Indexer] Unknown resolution batch: {updated}/{len(batch)} entries re-categorized")
            else:
                print("[AETHER] [Indexer] Empty response from LLM for unknown resolution batch")
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
    """Update IDA's wait-box and print progress to the output window.

    Must use ``execute_sync`` because it touches IDA UI.
    """
    msg = (
        f"Indexing: Batch {batch_num}/{total_batches}\n"
        f"Functions: {func_count}/{total_funcs}\n"
        f"Press Cancel to stop after current batch"
    )

    def _ui_update():
        try:
            ida_kernwin.replace_wait_box(msg)
        except Exception:
            pass  # wait-box may have been closed by user
        return 1

    ida_kernwin.execute_sync(_ui_update, ida_kernwin.MFF_FAST)
    print(f"[AETHER] [Indexer] Batch {batch_num}/{total_batches} — {func_count}/{total_funcs} functions indexed")


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
    model = config.get("indexing_model") or config.get("OPENAI_MODEL", "")

    client = create_openai_client_with_custom_ca(
        api_key, base_url, custom_ca, client_cert, client_key,
    )

    request_params: dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
    }

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

    try:
        # --- Step 1: Config & validation ---
        config = load_config()
        configured_tags = get_configured_tags(config)
        batch_size = int(config.get("indexing_batch_size", DEFAULT_BATCH_SIZE))
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
            func_list_container["funcs"] = collect_non_common_functions()
            return 1

        ida_kernwin.execute_sync(_collect, ida_kernwin.MFF_READ)
        func_list: List[Tuple[int, str]] = func_list_container["funcs"]

        if not func_list:
            on_failure("No non-library functions found in binary.")
            return

        print(f"[AETHER] [Indexer] Collected {len(func_list)} non-common functions")

        # --- Step 3: Generate pseudocode (main thread) ---
        pseudocode_container: dict = {"map": {}}

        def _gen_pseudo():
            pseudocode_container["map"] = generate_pseudocode_for_functions(func_list)
            return 1

        ida_kernwin.execute_sync(_gen_pseudo, ida_kernwin.MFF_READ)
        pseudocode_map: Dict[int, str] = pseudocode_container["map"]

        if not pseudocode_map:
            on_failure("Could not decompile any functions.")
            return

        # Filter func_list to only those with pseudocode
        func_list = [(a, n) for a, n in func_list if a in pseudocode_map]
        print(f"[AETHER] [Indexer] Generated pseudocode for {len(pseudocode_map)} functions")

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

        # Count entry points for prompt context
        entry_point_count = _count_entry_points(func_list)

        identifier = get_program_identifier()
        master_index = FunctionIndex()
        master_index.sha256 = identifier
        master_index.program_name = _get_binary_filename()
        master_index.total_function_count = len(func_list)
        master_index.indexing_state = "IN_PROGRESS"
        master_index.batch_metadata.total_batches = total_batches
        master_index.batch_metadata.start_time = start_time_ms

        index_filepath = get_index_filepath(identifier)
        print(f"[AETHER] [Indexer] Index file: {index_filepath}")
        print(f"[AETHER] [Indexer] Starting indexing: {len(func_list)} functions in {total_batches} batches (batch_size={batch_size})")

        # --- Step 6: Per-batch loop ---
        all_entries: List[FunctionEntry] = []

        for batch_idx, batch in enumerate(batches, start=1):
            if _cancellation_requested.is_set():
                print("[AETHER] [Indexer] Cancellation requested — saving partial progress.")
                master_index.indexing_state = "PARTIAL"
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure("Indexing cancelled by user. Partial progress saved.")
                return

            _update_progress(batch_idx, total_batches, master_index.size(), len(func_list))

            prompt = build_classification_prompt(
                batch, pseudocode_map, callees_map,
                batch_idx, total_batches, entry_point_count, configured_tags,
            )

            try:
                response_text, tokens = _call_llm(prompt, config)
            except Exception as exc:
                error_msg = f"LLM API error on batch {batch_idx}: {exc}"
                print(f"[AETHER] [Indexer] {error_msg}")
                master_index.indexing_state = "FAILED"
                master_index.batch_metadata.last_error = error_msg
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure(error_msg)
                return

            if not response_text:
                print(f"[AETHER] [Indexer] Empty LLM response for batch {batch_idx} — skipping")
                master_index.batch_metadata.last_error = f"Empty response on batch {batch_idx}"
                # Still count the batch as completed for resume purposes
                master_index.merge_and_persist([], batch_idx, total_batches, tokens)
                continue

            batch_entries = parse_classification_response(
                response_text, callees_map, configured_tags, tag_manager,
            )
            all_entries.extend(batch_entries)

            master_index.merge_and_persist(batch_entries, batch_idx, total_batches, tokens)
            print(f"[AETHER] [Indexer] Batch {batch_idx}/{total_batches}: parsed {len(batch_entries)} entries ({tokens} tokens)")

        # --- Step 7: Second-pass unknown resolution ---
        unknown_entries = collect_unknown_only_entries(all_entries)
        if unknown_entries:
            print(f"[AETHER] [Indexer] Running second-pass on {len(unknown_entries)} 'unknown' entries...")

            def _llm_for_unknowns(prompt: str) -> Tuple[str, int]:
                return _call_llm(prompt, config)

            resolved_count, unknown_tokens = resolve_unknown_entries(
                unknown_entries, configured_tags, tag_manager, _llm_for_unknowns,
            )
            master_index.total_tokens_used += unknown_tokens
            print(f"[AETHER] [Indexer] Re-categorized {resolved_count} of {len(unknown_entries)} unknowns")

        # --- Step 8: Finalise ---
        tag_manager.export_to_index(master_index)
        master_index.indexed = True
        master_index.indexing_state = "COMPLETED"
        master_index.indexing_progress = 100
        master_index.timestamp = int(time.time() * 1000)
        master_index.save_to_file()
        FunctionIndexManager.update_index(master_index, persist=False)

        print(f"[AETHER] [Indexer] Indexing complete: {master_index.size()} functions classified, {master_index.total_tokens_used} tokens used")
        on_success(master_index)

    except Exception as exc:
        tb = traceback.format_exc()
        print(f"[AETHER] [Indexer] Unhandled exception:\n{tb}")
        try:
            # Best-effort save
            master_index.indexing_state = "FAILED"  # noqa: F821 (may not be bound)
            master_index.batch_metadata.last_error = str(exc)
            master_index.save_to_file()
        except Exception:
            pass
        on_failure(f"Unhandled error: {exc}")
    finally:
        _indexing_in_progress.release()


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

    try:
        # --- Load existing index ---
        master_index = FunctionIndexManager.get_index()
        if not master_index.is_resumable():
            on_failure("Index is not in a resumable state.")
            return

        config = load_config()
        configured_tags = get_configured_tags(config)
        batch_size = int(config.get("indexing_batch_size", DEFAULT_BATCH_SIZE))
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
            func_list_container["funcs"] = collect_non_common_functions()
            return 1

        ida_kernwin.execute_sync(_collect, ida_kernwin.MFF_READ)
        all_funcs: List[Tuple[int, str]] = func_list_container["funcs"]

        # Filter out already-indexed
        remaining = [
            (a, n) for a, n in all_funcs
            if f"0x{a:08X}" not in already_indexed and f"0x{a:08x}" not in already_indexed
        ]

        if not remaining:
            print("[AETHER] [Indexer] All functions already indexed.")
            master_index.indexed = True
            master_index.indexing_state = "COMPLETED"
            master_index.indexing_progress = 100
            master_index.save_to_file()
            FunctionIndexManager.update_index(master_index, persist=False)
            on_success(master_index)
            return

        print(f"[AETHER] [Indexer] {len(remaining)} functions remaining to index")

        # Generate pseudocode for remaining
        pseudocode_container: dict = {"map": {}}

        def _gen_pseudo():
            pseudocode_container["map"] = generate_pseudocode_for_functions(remaining)
            return 1

        ida_kernwin.execute_sync(_gen_pseudo, ida_kernwin.MFF_READ)
        pseudocode_map: Dict[int, str] = pseudocode_container["map"]

        remaining = [(a, n) for a, n in remaining if a in pseudocode_map]
        if not remaining:
            print("[AETHER] [Indexer] No remaining functions could be decompiled.")
            master_index.indexed = True
            master_index.indexing_state = "COMPLETED"
            master_index.save_to_file()
            FunctionIndexManager.update_index(master_index, persist=False)
            on_success(master_index)
            return

        # Callees
        callees_container: dict = {"map": {}}

        def _build_callees():
            cmap: Dict[int, List[str]] = {}
            for addr, _ in remaining:
                cmap[addr] = get_callees(addr)
            callees_container["map"] = cmap
            return 1

        ida_kernwin.execute_sync(_build_callees, ida_kernwin.MFF_READ)
        callees_map: Dict[int, List[str]] = callees_container["map"]

        # Re-batch
        batches = split_into_batches(remaining, pseudocode_map, batch_size)
        new_total_batches = master_index.batch_metadata.completed_batches + len(batches)
        master_index.batch_metadata.total_batches = new_total_batches
        master_index.indexing_state = "IN_PROGRESS"
        entry_point_count = _count_entry_points(all_funcs)

        total_funcs_target = master_index.total_function_count or len(all_funcs)

        all_entries: List[FunctionEntry] = []

        for batch_idx_0, batch in enumerate(batches):
            batch_number = master_index.batch_metadata.completed_batches + 1

            if _cancellation_requested.is_set():
                print("[AETHER] [Indexer] Cancellation requested during resume — saving.")
                master_index.indexing_state = "PARTIAL"
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure("Indexing cancelled by user. Partial progress saved.")
                return

            _update_progress(batch_number, new_total_batches, master_index.size(), total_funcs_target)

            prompt = build_classification_prompt(
                batch, pseudocode_map, callees_map,
                batch_number, new_total_batches, entry_point_count, configured_tags,
            )

            try:
                response_text, tokens = _call_llm(prompt, config)
            except Exception as exc:
                error_msg = f"LLM API error on batch {batch_number}: {exc}"
                print(f"[AETHER] [Indexer] {error_msg}")
                master_index.indexing_state = "FAILED"
                master_index.batch_metadata.last_error = error_msg
                master_index.save_to_file()
                FunctionIndexManager.update_index(master_index, persist=False)
                on_failure(error_msg)
                return

            if not response_text:
                print(f"[AETHER] [Indexer] Empty response for batch {batch_number} — skipping")
                master_index.batch_metadata.last_error = f"Empty response on batch {batch_number}"
                master_index.merge_and_persist([], batch_number, new_total_batches, tokens)
                continue

            batch_entries = parse_classification_response(
                response_text, callees_map, configured_tags, tag_manager,
            )
            all_entries.extend(batch_entries)
            master_index.merge_and_persist(batch_entries, batch_number, new_total_batches, tokens)
            print(f"[AETHER] [Indexer] Resume batch {batch_number}/{new_total_batches}: {len(batch_entries)} entries")

        # Second-pass unknown resolution
        unknown_entries = collect_unknown_only_entries(all_entries)
        if unknown_entries:
            print(f"[AETHER] [Indexer] Running second-pass on {len(unknown_entries)} unknowns...")

            def _llm_fn(prompt: str) -> Tuple[str, int]:
                return _call_llm(prompt, config)

            resolved, unk_tokens = resolve_unknown_entries(
                unknown_entries, configured_tags, tag_manager, _llm_fn,
            )
            master_index.total_tokens_used += unk_tokens

        # Finalise
        tag_manager.export_to_index(master_index)
        master_index.indexed = True
        master_index.indexing_state = "COMPLETED"
        master_index.indexing_progress = 100
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
        _indexing_in_progress.release()


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
