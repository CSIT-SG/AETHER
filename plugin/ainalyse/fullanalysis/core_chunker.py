"""
core_chunker.py — Token-aware prompt-size management for the Fanalysis pipeline.

Strategy (applied in order until within budget):
  1. Aggressive second-pass minification of pseudocode
  2. Trim child-summary list (50 → 20 → 10 → 5 → 0)
  3. Smart truncation: keep head + tail of code with a marker
  4. Chunked multi-pass (caller responsibility via split_code_into_chunks)
"""

import re

# ---------------------------------------------------------------------------
# Budget constants
# ---------------------------------------------------------------------------

# Approximate tokens consumed by fanalysis-prompt.txt system prompt.
_SYSTEM_PROMPT_OVERHEAD = 2_500
# Tokens reserved for LLM output (tool calls + summaries).
_OUTPUT_TOKENS_RESERVE = 4_096
# Overhead for the minitree template wrapper and metadata lines.
_TEMPLATE_OVERHEAD = 512
# Total fixed overhead to subtract from the context limit.
FIXED_OVERHEAD = _SYSTEM_PROMPT_OVERHEAD + _OUTPUT_TOKENS_RESERVE + _TEMPLATE_OVERHEAD

# Tiktoken encoding used by most OpenAI-compatible models.
# Approximate for non-OpenAI models but still far better than char/4 guessing.
_TIKTOKEN_ENCODING = "cl100k_base"

# Child-summary truncation ladder: try each cap in turn.
_CHILD_SUMMARY_CAPS = [50, 20, 10, 5, 0]

# When chunking: target token size per code chunk (leaves room for the
# system prompt + child summaries + output in a single context window).
DEFAULT_CHUNK_TOKENS = 45_000


# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------

def count_tokens(text: str) -> int:
    """
    Count tokens using tiktoken when available, otherwise estimate via chars/4.

    The char/4 heuristic is deliberately conservative for code (real code is
    often closer to chars/3.5), so it will over-estimate which is the safe
    direction for budget decisions.
    """
    if not isinstance(text, str) or not text:
        return 0
    try:
        import tiktoken  # type: ignore
        enc = tiktoken.get_encoding(_TIKTOKEN_ENCODING)
        return len(enc.encode(text))
    except Exception:
        return len(text) // 4


def code_budget(context_limit: int) -> int:
    """Return the maximum tokens available for *code + child summaries*."""
    return max(0, context_limit - FIXED_OVERHEAD)


# ---------------------------------------------------------------------------
# Minification (second pass, more aggressive than core_ida_api.minify_c_code)
# ---------------------------------------------------------------------------

def aggressive_minify(c_text: str) -> str:
    """
    Second-pass minification applied only when the first pass leaves the
    prompt over budget.

    Removes address prefixes that cannot be used for comments anyway
    (cannotComment lines), collapses excess whitespace, and strips
    empty continuations of cast removals left by the first pass.
    """
    if not c_text:
        return ""

    # Drop the cannotComment prefix — these lines won't get comments so the
    # tag just wastes tokens.
    text = re.sub(r'^cannotComment\| ?', '', c_text, flags=re.MULTILINE)

    # Remove empty parentheses left over by cast stripping: "( )" / "()"
    text = re.sub(r'\(\s*\)', '', text)

    # Collapse runs of 3+ blank lines down to one.
    text = re.sub(r'\n{3,}', '\n\n', text)

    # Strip trailing whitespace on every line.
    text = '\n'.join(line.rstrip() for line in text.splitlines())

    return text.strip()


# ---------------------------------------------------------------------------
# Smart truncation
# ---------------------------------------------------------------------------

def smart_truncate(c_text: str, max_tokens: int, head_ratio: float = 0.65, tail_ratio: float = 0.20) -> tuple[str, bool]:
    """
    Truncate a code block to ``max_tokens`` tokens by keeping a head and a
    tail slice separated by a clear marker comment.

    Returns ``(truncated_text, was_truncated)``.

    The head preserves the function signature and setup; the tail preserves
    the return path and final logic.  The ratios are applied to the *line
    count* rather than the token count to keep the implementation simple —
    average token-per-line is used as the conversion factor.
    """
    if not c_text:
        return c_text, False

    current_tokens = count_tokens(c_text)
    if current_tokens <= max_tokens:
        return c_text, False

    lines = c_text.splitlines()
    if not lines:
        return c_text, False

    avg_tpl = current_tokens / max(len(lines), 1)
    max_lines = int(max_tokens / max(avg_tpl, 0.1))

    if max_lines >= len(lines):
        # Shouldn't happen but be safe
        return c_text, False

    # Guarantee at least 1 line each for head and tail.
    head_lines = max(1, int(max_lines * head_ratio))
    tail_lines = max(1, int(max_lines * tail_ratio))

    # If they overlap, give priority to head.
    if head_lines + tail_lines >= len(lines):
        return c_text, False

    skipped = len(lines) - head_lines - tail_lines
    marker = (
        f"\n/* ~~~ [{skipped} lines omitted — function too large for context window] ~~~ */\n"
    )

    truncated = '\n'.join(lines[:head_lines]) + marker + '\n'.join(lines[-tail_lines:])
    return truncated, True


# ---------------------------------------------------------------------------
# Main reduction entry-point
# ---------------------------------------------------------------------------

def reduce_to_budget(
    c_code: str,
    child_summaries: list[str],
    context_limit: int,
) -> tuple[str, list[str], str]:
    """
    Progressively shrink *c_code* and *child_summaries* until the combined
    token count fits within ``context_limit``.

    Returns ``(reduced_c_code, reduced_child_summaries, strategy_label)``
    where *strategy_label* is a human-readable string describing what was
    done (useful for logging).
    """
    budget = code_budget(context_limit)

    def total_tokens(code, summaries):
        summary_text = "\n".join(summaries)
        return count_tokens(code) + count_tokens(summary_text)

    # Fast-path: nothing to do.
    if total_tokens(c_code, child_summaries) <= budget:
        return c_code, child_summaries, "none"

    # --- Strategy 1: aggressive minification --------------------------------
    minified = aggressive_minify(c_code)
    if total_tokens(minified, child_summaries) <= budget:
        return minified, child_summaries, "aggressive_minify"
    c_code = minified  # carry the minified version forward

    # --- Strategy 2: trim child summaries -----------------------------------
    for cap in _CHILD_SUMMARY_CAPS:
        trimmed_summaries = child_summaries[:cap]
        if cap < len(child_summaries):
            trimmed_summaries = trimmed_summaries + [
                f"... and {len(child_summaries) - cap} more callee summaries omitted."
            ]
        if total_tokens(c_code, trimmed_summaries) <= budget:
            label = f"aggressive_minify + child_summaries_capped_at_{cap}"
            return c_code, trimmed_summaries, label
    # Worst case: no child summaries at all
    child_summaries = []

    # --- Strategy 3: smart truncation (generous head/tail) ------------------
    truncated, was_cut = smart_truncate(c_code, int(budget * 0.95))
    if was_cut:
        if total_tokens(truncated, child_summaries) <= budget:
            return truncated, child_summaries, "aggressive_minify + no_child_summaries + smart_truncate_65_20"
        c_code = truncated  # carry forward

    # --- Strategy 4: tighter truncation (smaller tail) ----------------------
    truncated2, was_cut2 = smart_truncate(c_code, int(budget * 0.90), head_ratio=0.55, tail_ratio=0.10)
    if was_cut2 or was_cut:
        if total_tokens(truncated2, []) <= budget:
            return truncated2, [], "aggressive_minify + no_child_summaries + smart_truncate_55_10"
        c_code = truncated2

    # --- Still over budget: return best effort and let caller chunk ----------
    return c_code, [], "best_effort_needs_chunking"


# ---------------------------------------------------------------------------
# Chunking for multi-pass analysis
# ---------------------------------------------------------------------------

def split_code_into_chunks(c_code: str, chunk_tokens: int = DEFAULT_CHUNK_TOKENS) -> list[str]:
    """
    Split pseudocode into line-aligned chunks of approximately *chunk_tokens*
    each.

    Chunk boundaries respect line boundaries so no address prefix is split
    mid-token.  The first chunk always includes the function signature
    (everything up to the first opening brace or the first 10 lines,
    whichever is larger) so all chunks share the declaration context.
    """
    if not c_code:
        return []

    lines = c_code.splitlines()
    if not lines:
        return []

    # Locate function signature end (first '{' line or first 10 lines).
    sig_end = 0
    for i, line in enumerate(lines):
        if '{' in line:
            sig_end = i + 1
            break
    sig_end = max(sig_end, min(10, len(lines)))
    signature_lines = lines[:sig_end]

    body_lines = lines[sig_end:]
    sig_tokens = count_tokens('\n'.join(signature_lines))
    body_chunk_tokens = max(1, chunk_tokens - sig_tokens)

    chunks = []
    current: list[str] = list(signature_lines)
    current_tokens = sig_tokens

    for line in body_lines:
        line_tokens = count_tokens(line) + 1  # +1 for the newline
        if current_tokens + line_tokens > chunk_tokens and len(current) > sig_end:
            chunks.append('\n'.join(current))
            # Next chunk starts with the signature for context continuity.
            current = list(signature_lines) + [line]
            current_tokens = sig_tokens + line_tokens
        else:
            current.append(line)
            current_tokens += line_tokens

    if current:
        chunks.append('\n'.join(current))

    return chunks if chunks else [c_code]
