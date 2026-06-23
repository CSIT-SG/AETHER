"""
Context Budget - Token accounting and threshold management.
"""

from dataclasses import dataclass, field
from typing import Optional

from .config import get_context_setting


@dataclass
class ContextBudget:
    """
    Manages token budget for LLM context window.
    
    Divides the context window into sections with reserved allocations:
    - System prompt: Fixed, never changes (fully cacheable)
    - Session summary: Updated every 10-20 turns (semi-cacheable)
    - Checkpoint state: Updated every 5-10 turns (semi-cacheable)
    - Relevant memories: Semantic retrieval results (changes per query)
    - Tool output buffer: Recent tool calls (changes every turn)
    - Working buffer: Response tokens + headroom
    
    Triggers summarization/truncation when thresholds are exceeded.
    
    Attributes:
        max_tokens: Total context window size (model-specific)
        system_reserve: Tokens reserved for system prompt
        summary_reserve: Tokens for session summary + checkpoint state
        memories_reserve: Tokens for semantically retrieved memories
        tool_buffer_reserve: Tokens for tool output history
        working_buffer: Remaining tokens for response + headroom
        
        summarize_trigger: Usage ratio that triggers summarization (0.8 = 80%)
        truncate_trigger: Usage ratio that triggers aggressive truncation (0.9 = 90%)
        hard_limit: Usage ratio that must not be exceeded (0.95 = 95%)
    """
    
    # Context window size (default: GPT-4o)
    max_tokens: int = 128_000
    
    # Section allocations (tokens)
    system_reserve: int = 2_000
    summary_reserve: int = 3_000  # Session summary + checkpoint state
    memories_reserve: int = 5_000  # Semantic retrieval results
    tool_buffer_reserve: int = 10_000  # Tool output history
    
    # Working buffer is calculated as remainder
    _working_buffer: Optional[int] = field(init=False, default=None)

    # Triggers (ratios) - Conservative thresholds to provide headroom for plan execution
    summarize_trigger: float = 0.60  # 60% - start summarizing old turns earlier
    truncate_trigger: float = 0.70   # 70% - aggressive truncation with more headroom
    hard_limit: float = 0.80         # 80% - must act immediately (emergency)
    
    # Current usage tracking
    _current_usage: int = field(default=0, init=False)
    _section_usage: dict = field(default_factory=dict, init=False)
    
    def __post_init__(self):
        """Calculate working buffer after initialization."""
        self.max_tokens = get_context_setting("budget", "max_tokens", default=self.max_tokens)
        self.system_reserve = get_context_setting("budget", "system_reserve", default=self.system_reserve)
        self.summary_reserve = get_context_setting("budget", "summary_reserve", default=self.summary_reserve)
        self.memories_reserve = get_context_setting("budget", "memories_reserve", default=self.memories_reserve)
        self.tool_buffer_reserve = get_context_setting("budget", "tool_buffer_reserve", default=self.tool_buffer_reserve)
        self.summarize_trigger = get_context_setting("budget", "summarize_trigger", default=self.summarize_trigger)
        self.truncate_trigger = get_context_setting("budget", "truncate_trigger", default=self.truncate_trigger)
        self.hard_limit = get_context_setting("budget", "hard_limit", default=self.hard_limit)
        self._working_buffer = self.max_tokens - (
            self.system_reserve +
            self.summary_reserve +
            self.memories_reserve +
            self.tool_buffer_reserve
        )
    
    @property
    def working_buffer(self) -> int:
        """Get the working buffer size (calculated)."""
        return self._working_buffer
    
    @property
    def allocated_tokens(self) -> int:
        """Get total allocated tokens (excluding working buffer)."""
        return (
            self.system_reserve +
            self.summary_reserve +
            self.memories_reserve +
            self.tool_buffer_reserve
        )
    
    @property
    def current_usage(self) -> int:
        """Get current token usage."""
        return self._current_usage
    
    @property
    def usage_ratio(self) -> float:
        """Get current usage as ratio of max_tokens."""
        if self.max_tokens == 0:
            return 0.0
        return self._current_usage / self.max_tokens
    
    @property
    def available_tokens(self) -> int:
        """Get remaining available tokens."""
        return max(0, self.max_tokens - self._current_usage)
    
    def update_usage(self, 
                     system_tokens: int,
                     summary_tokens: int,
                     memories_tokens: int,
                     tool_buffer_tokens: int,
                     conversation_tokens: int = 0) -> None:
        """
        Update current token usage from all sections.
        
        Args:
            system_tokens: Tokens used by system prompt
            summary_tokens: Tokens used by session summary
            memories_tokens: Tokens used by retrieved memories
            tool_buffer_tokens: Tokens used by tool output buffer
            conversation_tokens: Tokens used by conversation history
        """
        self._section_usage = {
            "system": system_tokens,
            "summary": summary_tokens,
            "memories": memories_tokens,
            "tool_buffer": tool_buffer_tokens,
            "conversation": conversation_tokens,
        }
        self._current_usage = sum(self._section_usage.values())
    
    def needs_summarization(self) -> bool:
        """Check if usage exceeds summarization trigger threshold."""
        return self.usage_ratio >= self.summarize_trigger
    
    def needs_truncation(self) -> bool:
        """Check if usage exceeds truncation trigger threshold."""
        return self.usage_ratio >= self.truncate_trigger
    
    def at_hard_limit(self) -> bool:
        """Check if usage is at or above hard limit."""
        return self.usage_ratio >= self.hard_limit
    
    def get_section_usage(self, section: str) -> int:
        """Get token usage for a specific section."""
        return self._section_usage.get(section, 0)
    
    def get_section_budget(self, section: str) -> int:
        """Get allocated budget for a specific section."""
        budgets = {
            "system": self.system_reserve,
            "summary": self.summary_reserve,
            "memories": self.memories_reserve,
            "tool_buffer": self.tool_buffer_reserve,
            "working": self.working_buffer,
        }
        return budgets.get(section, 0)
    
    def get_target_tokens(self, section: str) -> int:
        """
        Get target token count for a section based on current usage.
        
        When over budget, returns reduced target to bring usage under control.
        
        Args:
            section: Section name (system, summary, memories, tool_buffer, working)
            
        Returns:
            Target token count for the section
        """
        budget = self.get_section_budget(section)
        
        if self.at_hard_limit():
            # Aggressive reduction - aim for 50% of budget
            return max(int(budget * 0.5), 100)
        elif self.needs_truncation():
            # Moderate reduction - aim for 75% of budget
            return max(int(budget * 0.75), 100)
        elif self.needs_summarization():
            # Light reduction - aim for 90% of budget
            return max(int(budget * 0.9), 100)
        
        return budget
    
    def reset(self) -> None:
        """Reset usage tracking."""
        self._current_usage = 0
        self._section_usage = {}
    
    def summary(self) -> str:
        """Get human-readable budget summary."""
        lines = [
            f"Context Budget: {self._current_usage:,} / {self.max_tokens:,} tokens ({self.usage_ratio:.1%})",
            "",
            f"  System:       {self._section_usage.get('system', 0):>6,} / {self.system_reserve:>6,}",
            f"  Summary:      {self._section_usage.get('summary', 0):>6,} / {self.summary_reserve:>6,}",
            f"  Memories:     {self._section_usage.get('memories', 0):>6,} / {self.memories_reserve:>6,}",
            f"  Tool Buffer:  {self._section_usage.get('tool_buffer', 0):>6,} / {self.tool_buffer_reserve:>6,}",
            f"  Working:      {self._section_usage.get('conversation', 0):>6,} / {self.working_buffer:>6,}",
            "",
        ]
        
        if self.at_hard_limit():
            lines.append("  ⚠️  AT HARD LIMIT - Immediate action required!")
        elif self.needs_truncation():
            lines.append("  ⚠️  Truncation needed - reducing tool output history")
        elif self.needs_summarization():
            lines.append("  ⚡ Summarization recommended - compressing old turns")
        else:
            lines.append("  ✓ Within budget")
        
        return "\n".join(lines)
