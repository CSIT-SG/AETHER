"""
Conversation Summarizer - Compress old conversation turns.

Provides strategies for summarizing conversation history to reduce
token usage while preserving essential information.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import deque

from .config import get_context_setting


@dataclass
class ConversationTurn:
    """
    Represents a single turn in the conversation.
    
    Attributes:
        role: Message role (user, assistant, tool, system)
        content: Message content
        tokens: Estimated token count
        summary: Optional summary (for compressed turns)
        is_summary: Whether this turn is a summary
        tool_call_id: Optional tool call ID (for tool messages)
    """
    role: str
    content: str
    tokens: int = 0
    summary: Optional[str] = None
    is_summary: bool = False
    tool_call_id: Optional[str] = None
    
    def __post_init__(self):
        """Calculate token estimate."""
        if self.tokens == 0:
            self.tokens = len(self.content) // 4
    
    def to_message(self) -> Dict[str, Any]:
        """Convert to message format for LLM."""
        msg = {"role": self.role}
        if self.is_summary and self.summary:
            msg["content"] = self.summary
        else:
            msg["content"] = self.content
        # Include tool_call_id for tool messages
        if self.role == "tool" and self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        return msg
    
    def summarize(self, summary_text: str) -> None:
        """Mark this turn as summarized."""
        self.summary = summary_text
        self.is_summary = True
        self.tokens = len(summary_text) // 4


@dataclass
class ConversationSummary:
    """
    Summarized block of conversation turns.
    
    Replaces multiple turns with a single summary message.
    
    Attributes:
        turn_range: Range of turns covered (start, end)
        summary: Summary text
        tokens: Token count of summary
        key_findings: Important findings extracted
        tool_calls_made: Tools called in this range
    """
    turn_range: tuple  # (start, end)
    summary: str
    tokens: int = 0
    key_findings: List[str] = field(default_factory=list)
    tool_calls_made: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate token estimate."""
        self.tokens = len(self.summary) // 4
    
    def to_message(self) -> Dict[str, Any]:
        """Convert to message format for LLM."""
        return {
            "role": "system",
            "content": self.summary
        }


class ConversationSummarizer:
    """
    Summarizes conversation history to reduce token usage.
    
    Strategies:
    1. Sliding window: Keep recent N turns raw, summarize older
    2. Hierarchical: Summarize summaries for very old turns
    3. Key findings extraction: Preserve important information
    
    Attributes:
        keep_raw_turns: Number of recent turns to keep raw
        summary_prefix: Prefix for summary messages
        max_summary_tokens: Maximum tokens for a single summary
    """
    
    SUMMARY_PREFIX = """[CONVERSATION SUMMARY]
This summarizes previous conversation turns to save space.
Key findings and decisions are preserved below.

"""
    
    def __init__(self, 
                 keep_raw_turns: int = 10,
                 max_summary_tokens: int = 500):
        self.keep_raw_turns = get_context_setting("summarizer", "keep_raw_turns", default=keep_raw_turns)
        self.max_summary_tokens = get_context_setting("summarizer", "max_summary_tokens", default=max_summary_tokens)
        self._summaries: deque[ConversationSummary] = deque(maxlen=5)
    
    def summarize_turns(self, 
                        turns: List[ConversationTurn],
                        llm_client=None) -> ConversationSummary:
        """
        Summarize a list of conversation turns.
        
        Args:
            turns: Turns to summarize
            llm_client: Optional LLM client for intelligent summarization
            
        Returns:
            ConversationSummary object
        """
        if not turns:
            return ConversationSummary(
                turn_range=(0, 0),
                summary="[No conversation to summarize]"
            )
        
        # Extract key information
        tool_calls = []
        key_findings = []
        
        for turn in turns:
            if turn.role == "tool":
                # Extract tool call info
                tool_name = self._extract_tool_name(turn.content)
                if tool_name:
                    tool_calls.append(tool_name)
                
                # Check for findings
                if self._is_finding(turn.content):
                    key_findings.append(turn.content)
        
        # Generate summary
        if llm_client:
            summary = self._llm_summarize(turns, llm_client)
        else:
            summary = self._keyword_summarize(turns, tool_calls, key_findings)
        
        return ConversationSummary(
            turn_range=(0, len(turns)),
            summary=self.SUMMARY_PREFIX + summary,
            key_findings=key_findings,
            tool_calls_made=tool_calls
        )
    
    def _extract_tool_name(self, content: str) -> Optional[str]:
        """Extract tool name from tool result content."""
        # Common patterns
        if "Found" in content and "file" in content.lower():
            return "list_files"
        elif "Function" in content or "function" in content.lower():
            return "get_function_content"
        elif "Memory stored" in content:
            return "add_memory"
        elif "Found" in content and "relevant" in content.lower():
            return "search_memories"
        elif "File:" in content:
            return "get_file_summary"
        return None
    
    def _is_finding(self, content: str) -> bool:
        """Check if content represents an important finding."""
        finding_keywords = [
            "stored", "identified", "found", "detected",
            "suspicious", "malicious", "credential",
            "persistence", "exfil", "injection"
        ]
        content_lower = content.lower()
        return any(kw in content_lower for kw in finding_keywords)
    
    def _llm_summarize(self, 
                       turns: List[ConversationTurn],
                       llm_client) -> str:
        """Use LLM to generate intelligent summary."""
        # Build prompt for summarization
        turn_texts = []
        for turn in turns:
            turn_texts.append(f"{turn.role}: {turn.content}")
        
        prompt = f"""Summarize the following conversation turns, focusing on:
1. What analysis was performed
2. Key findings discovered
3. Tools used and their results
4. Any decisions or conclusions reached

Aim to keep the summary under {self.max_summary_tokens} tokens. Do not cut off
text mid-sentence; rewrite/compress naturally instead.

Conversation:
{' '.join(turn_texts)}

Summary:"""
        
        try:
            # Use LLM client to summarize
            response = llm_client.complete(prompt)
            return response
        except Exception:
            # Fallback to keyword summarization
            return self._keyword_summarize(turns, [], [])
    
    def _keyword_summarize(self,
                           turns: List[ConversationTurn],
                           tool_calls: List[str],
                           key_findings: List[str]) -> str:
        """Generate keyword-based summary without LLM."""
        lines = []
        
        # Count tool calls
        tool_counts: Dict[str, int] = {}
        for tool in tool_calls:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        lines.append(f"Analyzed {len(turns)} conversation turns.")
        
        if tool_counts:
            tool_summary = ", ".join(f"{count}x {name}" for name, count in tool_counts.items())
            lines.append(f"Tools used: {tool_summary}.")
        
        if key_findings:
            lines.append("Key findings:")
            for finding in key_findings:
                lines.append(f"  - {finding}")
        
        if not tool_counts and not key_findings:
            lines.append("No significant findings in this section.")
        
        return "\n".join(lines)
    
    def apply_sliding_window(self,
                             turns: List[ConversationTurn],
                             target_tokens: Optional[int] = None) -> List[ConversationTurn]:
        """
        Apply sliding window to keep recent turns raw, summarize older.
        
        Args:
            turns: All conversation turns
            target_tokens: Optional target token budget
            
        Returns:
            List of turns (some summarized, recent ones raw)
        """
        if len(turns) <= self.keep_raw_turns:
            return turns
        
        # Split into old (to summarize) and recent (keep raw)
        old_turns = turns[:-self.keep_raw_turns]
        recent_turns = turns[-self.keep_raw_turns:]
        
        # Summarize old turns
        if old_turns:
            summary = self.summarize_turns(old_turns)
            summary_turn = ConversationTurn(
                role="system",
                content=summary.summary,
                is_summary=True
            )
            return [summary_turn] + recent_turns
        
        return recent_turns
    
    def compress_to_budget(self,
                           turns: List[ConversationTurn],
                           budget_tokens: int) -> List[ConversationTurn]:
        """
        Compress conversation to fit within token budget.
        
        Progressively applies more aggressive compression:
        1. Summarize oldest turns
        2. Reduce summary detail
        3. Drop oldest summaries
        
        Args:
            turns: All conversation turns
            budget_tokens: Target token budget
            
        Returns:
            Compressed list of turns
        """
        # Calculate current usage
        current_tokens = sum(t.tokens for t in turns)
        
        if current_tokens <= budget_tokens:
            return turns
        
        # Start with sliding window
        result = self.apply_sliding_window(turns)
        current_tokens = sum(t.tokens for t in result)
        
        if current_tokens <= budget_tokens:
            return result
        
        # More aggressive: reduce keep_raw_turns
        for window_size in [8, 6, 4, 2]:
            result = self.apply_sliding_window(turns)
            # Actually re-apply with smaller window
            if len(turns) > window_size:
                old_turns = turns[:-window_size]
                recent_turns = turns[-window_size:]
                if old_turns:
                    summary = self.summarize_turns(old_turns)
                    result = [ConversationTurn(
                        role="system",
                        content=summary.summary,
                        is_summary=True
                    )] + recent_turns
            
            current_tokens = sum(t.tokens for t in result)
            if current_tokens <= budget_tokens:
                return result
        
        # Most aggressive: keep only last few turns
        max_turns = max(1, budget_tokens // 500)  # ~500 tokens per turn
        return turns[-max_turns:]
    
    def get_statistics(self, turns: List[ConversationTurn]) -> Dict[str, Any]:
        """Get statistics about conversation turns."""
        total_tokens = sum(t.tokens for t in turns)
        summary_count = sum(1 for t in turns if t.is_summary)
        
        by_role: Dict[str, int] = {}
        for turn in turns:
            by_role[turn.role] = by_role.get(turn.role, 0) + 1
        
        return {
            "total_turns": len(turns),
            "total_tokens": total_tokens,
            "summary_turns": summary_count,
            "raw_turns": len(turns) - summary_count,
            "by_role": by_role,
            "avg_tokens_per_turn": total_tokens / len(turns) if turns else 0,
        }
    
    def summary(self, turns: List[ConversationTurn]) -> str:
        """Get human-readable summary of conversation state."""
        stats = self.get_statistics(turns)
        lines = [
            f"Conversation: {stats['total_turns']} turns, {stats['total_tokens']:,} tokens",
            f"  Raw turns: {stats['raw_turns']}",
            f"  Summarized: {stats['summary_turns']}",
            f"  Avg tokens/turn: {stats['avg_tokens_per_turn']:.0f}",
        ]
        
        if stats['by_role']:
            lines.append("  By role:")
            for role, count in stats['by_role'].items():
                lines.append(f"    {role}: {count}")
        
        return "\n".join(lines)
