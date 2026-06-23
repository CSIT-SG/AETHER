"""
Block Buffer - Tool-call-aware conversation management.

Groups related messages (assistant tool_calls + tool responses) into atomic
blocks that won't be split during summarization, preserving tool_call_id
compatibility with Azure/OpenRouter.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import deque

from .config import get_context_setting

logger = logging.getLogger(__name__)


@dataclass
class ConversationBlock:
    """
    A block of conversation messages that should be kept together.

    Typically contains:
    - Assistant message (may include tool_calls)
    - Corresponding tool response messages (if tool_calls exist)

    This ensures tool_call_id pairing is never broken during summarization.

    Attributes:
        messages: List of messages in this block
        tokens: Estimated token count
        is_summarized: Whether this block has been summarized
        summary: Optional summary text (if summarized)
        has_tool_calls: Whether block contains tool calls
        has_tool_response: Whether block contains tool responses
    """
    messages: List[Dict[str, Any]] = field(default_factory=list)
    tokens: int = 0
    is_summarized: bool = False
    summary: Optional[str] = None
    has_tool_calls: bool = False
    has_tool_response: bool = False

    def add_message(self, message: Dict[str, Any]) -> None:
        """Add a message to this block."""
        self.messages.append(message)
        # Recalculate tokens
        content = message.get("content") or ""
        self.tokens = sum(
            len((m.get("content") or "")) // 4
            for m in self.messages
        )

        # Track if block has tool calls
        if message.get("role") == "assistant" and message.get("tool_calls"):
            self.has_tool_calls = True
        
        # Track if block has tool responses
        if message.get("role") == "tool":
            self.has_tool_response = True
    
    def to_message_dicts(self) -> List[Dict[str, Any]]:
        """Convert block to list of message dicts for LLM API."""
        if self.is_summarized and self.summary:
            # Return summary as a single system message
            return [{
                "role": "system",
                "content": f"[CONVERSATION SUMMARY]\n{self.summary}"
            }]
        return self.messages
    
    def get_tool_call_ids(self) -> List[str]:
        """Extract all tool call IDs from this block."""
        ids = []
        for msg in self.messages:
            tool_calls = msg.get("tool_calls") or []
            if msg.get("role") == "assistant" and tool_calls:
                for tc in tool_calls:
                    if isinstance(tc, dict):
                        ids.append(tc.get("id", ""))
                    elif hasattr(tc, 'id'):
                        ids.append(tc.id)
        return ids
    
    def get_tool_response_ids(self) -> List[str]:
        """Extract all tool_call_ids from tool responses in this block."""
        ids = []
        for msg in self.messages:
            if msg.get("role") == "tool" and "tool_call_id" in msg:
                ids.append(msg["tool_call_id"])
        return ids
    
    def summarize(self, summary_text: str) -> None:
        """Mark this block as summarized with given summary text."""
        self.summary = summary_text
        self.is_summarized = True
        # Recalculate tokens (summary is typically much shorter)
        self.tokens = len(summary_text) // 4 + 20  # +20 for wrapper text


class BlockBuffer:
    """
    Manages conversation blocks with summarization support.

    Maintains a buffer of conversation blocks and provides methods to:
    - Add new messages (automatically grouped into blocks)
    - Summarize older blocks into variable summary
    - Merge variable summary into session summary when threshold reached
    - Convert to message list for LLM API

    Two-component summary system:
    - Session Summary: Persistent, accumulates major findings across entire session
    - Variable Summary: Rolling, holds recent conversation history until threshold

    Attributes:
        blocks: Deque of conversation blocks
        max_raw_blocks: Maximum blocks to keep in raw (non-summarized) form
        max_tokens: Maximum total tokens before summarization triggered
        session_summary: Persistent session-wide findings (never deleted, only updated)
        variable_summary: Rolling conversation summary (reset after merge to session)
        variable_summary_threshold: Char threshold to trigger merge (default 8000)
    """

    # Threshold for variable summary before merging into session summary
    VARIABLE_SUMMARY_THRESHOLD = get_context_setting("block_buffer", "variable_summary_threshold", default=3000)
    # Target size for session summary after consolidation
    SESSION_SUMMARY_TARGET = get_context_setting("block_buffer", "session_summary_target", default=2000)
    # Per-message target for locally generated summary notes. Long messages are
    # summarized into metadata/identifier notes instead of being sliced.
    SUMMARY_NOTE_TARGET = get_context_setting("block_buffer", "summary_note_target", default=600)

    def __init__(self, max_raw_blocks: int = 10, max_tokens: int = 50_000):
        self.blocks: deque[ConversationBlock] = deque()
        self.max_raw_blocks = get_context_setting("block_buffer", "max_raw_blocks", default=max_raw_blocks)
        self.max_tokens = get_context_setting("block_buffer", "max_tokens", default=max_tokens)
        self._current_tokens = 0
        
        # Two-component summary system
        self.session_summary: str = ""           # Persistent session findings
        self.variable_summary: str = ""          # Rolling conversation summary
        self.variable_summary_threshold: int = self.VARIABLE_SUMMARY_THRESHOLD
    
    @property
    def current_tokens(self) -> int:
        """Get current total token count."""
        return self._current_tokens
    
    @property
    def raw_block_count(self) -> int:
        """Get count of non-summarized blocks."""
        return sum(1 for b in self.blocks if not b.is_summarized)
    
    @property
    def summarized_block_count(self) -> int:
        """Get count of summarized blocks."""
        return sum(1 for b in self.blocks if b.is_summarized)
    
    def add_message(self, message: Dict[str, Any]) -> None:
        """
        Add a message, automatically grouping into blocks.

        Block boundaries:
        - Assistant message starts a new block
        - Tool responses are added to the most recent block that has tool_calls
        - User messages start a new block
        """
        role = message.get("role", "unknown")

        # Determine if we need a new block
        need_new_block = False

        if not self.blocks:
            need_new_block = True
        elif role == "assistant":
            # Assistant always starts a new block
            need_new_block = True
        elif role == "user":
            # User messages start a new turn block. This preserves follow-up
            # queries that arrive after a completed assistant response.
            need_new_block = True
        elif role == "tool":
            # Tool response - add to the most recent block with tool_calls
            if not self.blocks:
                # Orphan tool response - create new block (shouldn't happen)
                need_new_block = True
            else:
                # Find the most recent block that has tool_calls
                # (not necessarily the last block, in case of multiple tool responses)
                found_block = False
                for block in reversed(self.blocks):
                    if block.has_tool_calls:
                        # Add to this block
                        block.add_message(message)
                        self._current_tokens += len((message.get("content") or "")) // 4
                        found_block = True
                        break
                
                if not found_block:
                    # No block with tool_calls - create new block
                    need_new_block = True
                else:
                    return

        if need_new_block:
            new_block = ConversationBlock()
            self.blocks.append(new_block)
            # Add message to the new block
            self.blocks[-1].add_message(message)
            self._current_tokens += len((message.get("content") or "")) // 4
        else:
            self.blocks[-1].add_message(message)
            self._current_tokens += len((message.get("content") or "")) // 4
    
    def needs_summarization(self) -> bool:
        """Check if buffer needs summarization."""
        # Trigger if too many raw blocks
        if self.raw_block_count > self.max_raw_blocks:
            return True
        # Trigger if over token budget
        if self._current_tokens > self.max_tokens:
            return True
        return False

    def needs_aggressive_truncation(self) -> bool:
        """Check if buffer needs aggressive truncation (dropping blocks)."""
        # Trigger if way over token budget (>150%)
        if self._current_tokens > self.max_tokens * 1.5:
            return True
        return False

    def summarize_oldest_blocks(self, num_blocks: int = None, summarizer_agent=None, plan=None) -> int:
        """
        Summarize the oldest non-summarized blocks.

        Strategy:
        1. Take the oldest N blocks (default 5)
        2. Generate ONE summary for all blocks together, grouped by plan action
        3. REMOVE the summarized blocks from the buffer
        4. Add summary to variable summary (triggers merge if threshold reached)

        IMPORTANT: We must keep COMPLETE assistant+tool pairs.
        We cannot summarize a block if the NEXT block is a tool response that depends on it.

        Args:
            num_blocks: Number of blocks to summarize (default: batch of 5)
            summarizer_agent: Optional SummarizerAgent for LLM-based summarization
            plan: Optional Plan object for grouping summaries by action

        Returns:
            Number of blocks summarized
        """
        # Get raw blocks that can be summarized
        raw_blocks_no_tools = [
            b for b in self.blocks
            if not b.is_summarized and not b.has_tool_calls and not b.has_tool_response
        ]

        raw_blocks_complete = [
            b for b in self.blocks
            if not b.is_summarized and b.has_tool_calls and b.has_tool_response
        ]

        # Combine: prefer no-tools, then complete blocks
        if raw_blocks_no_tools:
            raw_blocks = raw_blocks_no_tools
        elif raw_blocks_complete:
            raw_blocks = raw_blocks_complete
        else:
            return 0

        # Calculate how many to summarize - default to batch of 5
        if num_blocks is None:
            num_blocks = min(5, len(raw_blocks))

        # CRITICAL: Keep the last 3 blocks raw to ensure complete assistant+tool pairs
        # This ensures any tool response has its assistant message in the same or adjacent block
        blocks_to_keep_raw = min(3, len(raw_blocks))
        max_summarize = len(raw_blocks) - blocks_to_keep_raw

        if max_summarize <= 0:
            return 0  # Not enough blocks to summarize safely

        num_blocks = min(num_blocks, max_summarize)
        blocks_to_summarize = raw_blocks[:num_blocks]

        # Generate summary
        if summarizer_agent and num_blocks >= 3:
            batch_summary = summarizer_agent.summarize_blocks(blocks_to_summarize, plan=plan)
            summary_text = batch_summary.chronological_summary
        else:
            # Rule-based summary
            summary_lines = []
            for block in blocks_to_summarize:
                summary_lines.append(self._generate_summary(block))
            summary_text = "\n".join(summary_lines)

        # REMOVE the summarized blocks from the buffer
        for block in blocks_to_summarize:
            self.blocks.remove(block)
            self._current_tokens -= block.tokens

        # Recalculate total tokens
        self._current_tokens = sum(b.tokens for b in self.blocks)

        # Add to variable summary (triggers merge if threshold reached)
        self.add_to_variable_summary(summary_text, summarizer_agent=summarizer_agent)

        logger.info(f"Summarized and removed {len(blocks_to_summarize)} blocks ({len(summary_text)} chars)")

        return len(blocks_to_summarize)

    def add_to_variable_summary(self, summary_text: str, summarizer_agent=None) -> bool:
        """
        Add summary text to variable summary, trigger merge if threshold exceeded.

        Args:
            summary_text: Summary text to add to variable summary
            summarizer_agent: Optional SummarizerAgent for meta-summarization

        Returns:
            True if merge was triggered, False otherwise
        """
        # Append to variable summary
        if self.variable_summary:
            self.variable_summary += "\n\n" + summary_text
        else:
            self.variable_summary = summary_text

        logger.debug(f"Added to variable summary: {len(summary_text)} chars, total: {len(self.variable_summary)} chars")

        # Check if threshold exceeded
        if len(self.variable_summary) >= self.variable_summary_threshold:
            logger.info(f"Variable summary reached threshold ({len(self.variable_summary)} chars), triggering merge...")
            if summarizer_agent:
                self.merge_variable_into_session(summarizer_agent)
                return True
            else:
                logger.warning("No summarizer_agent available for merge, keeping variable summary")

        return False

    def merge_variable_into_session(self, summarizer_agent) -> None:
        """
        Merge variable summary into session summary using LLM meta-summarization.

        Combines current session summary with variable summary, produces
        consolidated session summary, and resets variable summary.

        Args:
            summarizer_agent: SummarizerAgent for meta-summarization
        """
        if not self.variable_summary:
            logger.debug("No variable summary to merge")
            return

        logger.info(f"Merging variable summary ({len(self.variable_summary)} chars) into session summary ({len(self.session_summary)} chars)...")

        try:
            # Call LLM to consolidate
            consolidated = summarizer_agent.meta_summarize(
                session_summary=self.session_summary,
                variable_summary=self.variable_summary,
                target_length=self.SESSION_SUMMARY_TARGET
            )

            # Update session summary with consolidated result
            self.session_summary = consolidated

            # Reset variable summary
            old_variable_len = len(self.variable_summary)
            self.variable_summary = ""

            logger.info(f"Merge complete: session summary now {len(self.session_summary)} chars, freed {old_variable_len} chars from variable")

        except Exception as e:
            logger.error(f"Failed to merge variable into session: {e}")
            # Keep variable summary intact on failure, will retry next time

    def get_session_summary(self) -> str:
        """Get current session summary."""
        return self.session_summary

    def get_variable_summary(self) -> str:
        """Get current variable summary."""
        return self.variable_summary

    def get_combined_summary(self) -> str:
        """Get combined session and variable summary."""
        parts = []
        if self.session_summary:
            parts.append(f"Session Summary:\n{self.session_summary}")
        if self.variable_summary:
            parts.append(f"Variable Summary:\n{self.variable_summary}")
        return "\n\n".join(parts) if parts else ""

    def clear_summaries(self) -> None:
        """Clear both session and variable summaries."""
        self.session_summary = ""
        self.variable_summary = ""

    def drop_oldest_blocks(self, num_blocks: int = 1) -> int:
        """
        Drop the oldest blocks entirely.

        Args:
            num_blocks: Number of blocks to drop

        Returns:
            Number of tokens freed
        """
        tokens_freed = 0
        for _ in range(min(num_blocks, len(self.blocks))):
            if self.blocks:
                oldest = self.blocks.popleft()
                tokens_freed += oldest.tokens
        self._current_tokens -= tokens_freed
        return tokens_freed

    def truncate_to_budget(self, target_tokens: int = None) -> int:
        """
        Aggressively truncate to get under budget.

        Args:
            target_tokens: Target token count (uses max_tokens if None)

        Returns:
            Number of tokens freed
        """
        tokens_freed = 0
        
        # Use provided target or fall back to max_tokens
        budget_limit = target_tokens if target_tokens is not None else self.max_tokens

        # First, summarize ALL raw blocks (not just half)
        raw_blocks = [b for b in self.blocks if not b.is_summarized]
        for block in raw_blocks:
            summary = self._generate_summary(block)
            block.summarize(summary)
            old_tokens = block.tokens
            new_tokens = len(summary) // 4 + 20
            self._current_tokens -= (old_tokens - new_tokens)
            tokens_freed += (old_tokens - new_tokens)

        # If still over budget, drop oldest blocks aggressively
        # Keep only the 3 most recent blocks
        while self._current_tokens > budget_limit and len(self.blocks) > 3:
            dropped = self.drop_oldest_blocks(1)
            if dropped == 0:  # No more blocks to drop
                break
            tokens_freed += dropped

        return tokens_freed
    
    def _generate_summary(self, block: ConversationBlock) -> str:
        """Generate a summary for a single block.

        Summarizes the block as a compact narrative instead of a turn log.
        """
        tool_calls = []
        user_notes = []
        assistant_notes = []
        evidence_notes = []

        for msg in block.messages:
            role = msg.get("role")
            tool_calls_value = msg.get("tool_calls") or []
            if role == "assistant" and tool_calls_value:
                for tc in tool_calls_value:
                    if isinstance(tc, dict):
                        tool_calls.append(tc.get("function", {}).get("name", "unknown"))
                    elif hasattr(tc, 'function'):
                        tool_calls.append(tc.function.name)

            content = msg.get("content") or ""
            if not content or len(content) <= 20:
                continue

            if role == "user":
                user_notes.append(self._summarize_text_for_cap(content, "user message"))
            elif role == "assistant" and not tool_calls_value:
                assistant_notes.append(self._summarize_text_for_cap(content, "assistant response"))
            elif role == "tool":
                evidence = self._summarize_tool_content(content)
                if evidence:
                    evidence_notes.append(evidence)

        sentences = []
        if user_notes:
            sentences.append(f"The discussion focused on {self._join_notes(user_notes)}.")
        if tool_calls:
            unique_tools = ", ".join(dict.fromkeys(tool_calls))
            sentences.append(f"Evidence was gathered with {unique_tools}.")
        if evidence_notes:
            sentences.append(f"The retrieved evidence showed {self._join_notes(evidence_notes)}.")
        if assistant_notes:
            sentences.append(f"The analysis concluded that {self._join_notes(assistant_notes)}.")

        if not sentences:
            return f"[{len(block.messages)} messages in block]"

        return " ".join(sentences)

    def _summarize_tool_content(self, content: str) -> str:
        if "Found" in content:
            match = re.search(r'Found (\d+) file', content)
            if match:
                return f"{match.group(1)} file(s) matched the query"
            return self._summarize_text_for_cap(content, "tool result")
        if "stored" in content.lower() or "Memory stored" in content:
            match = re.search(r'ID: ([a-f0-9-]+)', content)
            if match:
                return f"a memory item was stored ({match.group(1)[:8]}...)"
            return self._summarize_text_for_cap(content, "tool result")
        if "Error" in content or "not found" in content.lower():
            return self._summarize_text_for_cap(content, "tool result")
        if "===" in content:
            match = re.search(r'=== (.+?) ===', content)
            if match:
                filename = match.group(1).split('/')[-1]
                return f"{filename} was read"
            return f"tool output of {len(content)} characters was read"
        return self._summarize_text_for_cap(content, "tool result")

    @staticmethod
    def _normalize_text(text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    def _summarize_text_for_cap(self, text: str, label: str) -> str:
        normalized = self._normalize_text(text)
        if len(normalized) <= self.SUMMARY_NOTE_TARGET:
            return normalized

        identifiers = self._extract_summary_identifiers(normalized)
        if identifiers:
            return (
                f"a long {label} ({len(normalized)} chars) mentioning "
                f"{', '.join(identifiers)}"
            )
        return f"a long {label} ({len(normalized)} chars)"

    @staticmethod
    def _extract_summary_identifiers(text: str, limit: int = 12) -> List[str]:
        quoted = re.findall(r"`([^`]{1,80})`|'([^']{1,80})'|\"([^\"]{1,80})\"", text)
        candidates: list[str] = []
        for groups in quoted:
            for value in groups:
                if value:
                    candidates.append(value)

        candidates.extend(
            re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", text)
        )

        filtered: list[str] = []
        stopwords = {
            "this", "that", "with", "from", "have", "function", "analysis",
            "message", "assistant", "response", "content", "summary",
        }
        for candidate in candidates:
            normalized = candidate.strip()
            if not normalized or normalized.lower() in stopwords:
                continue
            if normalized not in filtered:
                filtered.append(normalized)
            if len(filtered) >= limit:
                break
        return filtered

    @staticmethod
    def _join_notes(notes: List[str]) -> str:
        unique_notes = list(dict.fromkeys(note for note in notes if note))
        if not unique_notes:
            return ""
        if len(unique_notes) == 1:
            return unique_notes[0]
        return "; ".join(unique_notes)
    
    def get_messages(self) -> List[Dict[str, Any]]:
        """
        Convert all blocks to message list for LLM API.

        Preserves tool_call_id pairing by keeping blocks intact.
        """
        messages = []
        for block in self.blocks:
            messages.extend(block.to_message_dicts())
        return messages

    def get_consolidated_summary(self) -> str:
        """
        Get a single consolidated summary of all summarized blocks.

        Returns:
            Single summary string combining session and variable summary
        """
        return self.get_combined_summary()

    def get_summarized_conversation_history(self) -> List[Dict[str, Any]]:
        """
        Get conversation history with two-component summary system.

        Returns:
            List of message dicts with:
            - Session summary (persistent findings)
            - Variable summary (recent conversation history)
            - Raw blocks (most recent turns)
        """
        result = []

        # Get combined summary (session + variable)
        combined = self.get_combined_summary()

        # Add combined summary as a single system message if non-empty
        if combined:
            result.append({
                "role": "system",
                "content": f"[CONVERSATION SUMMARY]\n{combined}"
            })

        # Add all raw blocks
        for block in self.blocks:
            result.extend(block.to_message_dicts())

        return result

    def drop_oldest_blocks(self, num_blocks: int = 1) -> int:
        """
        Drop the oldest blocks entirely.
        
        Used as last-resort truncation when summarization isn't enough.
        
        Args:
            num_blocks: Number of blocks to drop
            
        Returns:
            Number of tokens freed
        """
        tokens_freed = 0
        for _ in range(min(num_blocks, len(self.blocks))):
            if self.blocks:
                oldest = self.blocks.popleft()
                tokens_freed += oldest.tokens
        
        self._current_tokens -= tokens_freed
        return tokens_freed
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        return {
            "total_blocks": len(self.blocks),
            "raw_blocks": self.raw_block_count,
            "summarized_blocks": self.summarized_block_count,
            "total_tokens": self._current_tokens,
            "avg_tokens_per_block": self._current_tokens / len(self.blocks) if self.blocks else 0,
        }
    
    def clear(self) -> None:
        """Clear all blocks."""
        self.blocks.clear()
        self._current_tokens = 0
