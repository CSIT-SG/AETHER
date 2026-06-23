"""
Tool Output Buffer - Intelligent truncation of tool call history.

Manages tool call history with progressive truncation strategies to stay
within token budget while preserving important information.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum
from collections import deque

from .config import get_context_setting


class TruncationStrategy(Enum):
    """Truncation strategies for tool outputs."""
    FULL = "full"              # Keep complete output
    METADATA_ONLY = "metadata"  # Keep only tool name + brief summary
    STATUS_ONLY = "status"      # Keep only success/failure
    SUMMARIZED = "summarized"   # Group multiple calls into summary
    DROPPED = "dropped"         # Remove entirely


# Tool priority for retention (higher = keep longer)
TOOL_PRIORITY: Dict[str, str] = {
    "add_memory": "HIGH",        # Findings are critical
    "search_memories": "HIGH",   # Shows reasoning
    "get_function_content": "MEDIUM",  # Code examination
    "get_file_summary": "LOW",         # Structure only
    "list_files": "LOW",               # One-time discovery
    "get_memory_statistics": "LOW",
}


@dataclass
class ToolCallRecord:
    """
    Records a single tool call with its result.
    
    Attributes:
        name: Tool name
        arguments: Dict[str, Any]
        result: Tool result (string)
        tool_call_id: Unique ID from LLM tool call
        priority: Tool priority level (HIGH, MEDIUM, LOW)
        tokens: Estimated token count of the full record
        strategy: Current truncation strategy
    """
    name: str
    arguments: Dict[str, Any]
    result: str
    tool_call_id: str = ""
    priority: str = "MEDIUM"
    tokens: int = 0
    strategy: TruncationStrategy = TruncationStrategy.FULL
    
    def __post_init__(self):
        """Calculate token estimate and priority."""
        if self.priority == "MEDIUM":
            self.priority = TOOL_PRIORITY.get(self.name, "MEDIUM")
        # Rough token estimate: ~1 token per 4 characters
        self.tokens = len(str({
            "name": self.name,
            "arguments": self.arguments,
            "result": self.result,
            "id": self.tool_call_id
        })) // 4
    
    def get_truncated_content(self) -> str:
        """Get truncated representation based on current strategy."""
        if self.strategy == TruncationStrategy.FULL:
            return self.result
        elif self.strategy == TruncationStrategy.METADATA_ONLY:
            # Extract key info from result
            return self._metadata_summary()
        elif self.strategy == TruncationStrategy.STATUS_ONLY:
            return self._status_summary()
        elif self.strategy == TruncationStrategy.SUMMARIZED:
            return self._summarized()
        else:  # DROPPED
            return ""
    
    def _metadata_summary(self) -> str:
        """Generate metadata-only summary."""
        # Try to extract meaningful metadata from result
        result_lower = self.result.lower()
        
        if "found" in result_lower and "file" in result_lower:
            # File listing result
            return f"list_files: {self.result.split(':')[0] if ':' in self.result else 'files listed'}"
        elif "function" in result_lower or "class" in result_lower:
            # File summary result
            if "functions" in result_lower:
                # Try to extract count
                import re
                match = re.search(r'(\d+)\s+function', result_lower)
                func_count = match.group(1) if match else "?"
                return f"{self.name}: {func_count} functions found"
            return f"{self.name}: structure examined"
        elif "memory" in result_lower and ("stored" in result_lower or "added" in result_lower):
            return f"{self.name}: memory stored"
        elif "error" in result_lower or "not found" in result_lower:
            return f"{self.name}: {self.result[:50]}..."
        
        # Generic metadata summary
        args_summary = ", ".join(f"{k}={v}" for k, v in list(self.arguments.items())[:3])
        return f"{self.name}({args_summary}) → {len(self.result)} chars"
    
    def _status_summary(self) -> str:
        """Generate status-only summary."""
        result_lower = self.result.lower()
        if "error" in result_lower or "not found" in result_lower:
            return f"{self.name}: FAILED"
        elif "success" in result_lower or "stored" in result_lower or "found" in result_lower:
            return f"{self.name}: SUCCESS"
        else:
            return f"{self.name}: OK"
    
    def _summarized(self) -> str:
        """Generate summarized representation."""
        return f"[{self.name} call]"
    
    def to_message(self) -> Dict[str, Any]:
        """Convert to message format for LLM."""
        if self.strategy == TruncationStrategy.DROPPED:
            return {}
        
        return {
            "role": "tool",
            "content": self.get_truncated_content()
        }


@dataclass
class ToolCallGroup:
    """
    Groups multiple tool calls for batch summarization.
    
    Used when applying aggressive truncation to compress
    sequences of similar tool calls.
    """
    tool_name: str
    calls: List[ToolCallRecord] = field(default_factory=list)
    summary: str = ""
    
    def add(self, record: ToolCallRecord) -> None:
        """Add a tool call to the group."""
        self.calls.append(record)
    
    def generate_summary(self) -> str:
        """Generate summary for the group."""
        if not self.calls:
            return ""
        
        success_count = sum(
            1 for c in self.calls 
            if "error" not in c.result.lower() and "not found" not in c.result.lower()
        )
        fail_count = len(self.calls) - success_count
        
        self.summary = (
            f"Previous {len(self.calls)} {self.tool_name} calls: "
            f"{success_count} successful"
            f"{f', {fail_count} failed' if fail_count > 0 else ''}"
        )
        return self.summary
    
    def to_message(self) -> Dict[str, Any]:
        """Convert group summary to message format."""
        if not self.summary:
            self.generate_summary()
        return {
            "role": "tool",
            "content": self.summary
        }


class ToolOutputBuffer:
    """
    Manages tool call history with intelligent truncation.
    
    Maintains a ring buffer of tool call records and applies
    progressive truncation strategies when approaching token limits.
    
    Truncation is applied in order:
    1. Drop oldest low-priority tool calls
    2. Summarize old tool outputs (group similar calls)
    3. Reduce to metadata-only (tool name + brief result)
    4. Reduce to status-only (success/failure)
    5. Drop entire turns (oldest first)
    
    Attributes:
        max_records: Maximum number of records to keep
        max_tokens: Maximum tokens for the buffer
        records: Deque of tool call records
    """
    
    def __init__(self, max_records: int = 100, max_tokens: int = 10_000):
        self.max_records = get_context_setting("tool_buffer", "max_records", default=max_records)
        self.max_tokens = get_context_setting("tool_buffer", "max_tokens", default=max_tokens)
        self.records: deque[ToolCallRecord] = deque(maxlen=self.max_records)
        self._current_tokens = 0
    
    @property
    def current_tokens(self) -> int:
        """Get current token usage."""
        return self._current_tokens
    
    def add(self, name: str, arguments: Dict[str, Any], result: str, tool_call_id: str = "") -> ToolCallRecord:
        """
        Add a new tool call record.
        
        Args:
            name: Tool name
            arguments: Tool arguments
            result: Tool result
            tool_call_id: Tool call ID
            
        Returns:
            The created ToolCallRecord
        """
        # If record with this ID already exists, update it instead of adding
        if tool_call_id:
            for record in self.records:
                if record.tool_call_id == tool_call_id:
                    self._current_tokens -= record.tokens
                    record.result = result
                    record.__post_init__()
                    self._current_tokens += record.tokens
                    return record

        record = ToolCallRecord(
            name=name,
            arguments=arguments,
            result=result,
            tool_call_id=tool_call_id
        )
        
        # Remove oldest if at capacity
        if len(self.records) >= self.max_records:
            oldest = self.records[0]
            self._current_tokens -= oldest.tokens
        
        self.records.append(record)
        self._current_tokens += record.tokens
        
        return record

    def get_record_by_id(self, tool_call_id: str) -> Optional[ToolCallRecord]:
        """Get a record by its tool call ID."""
        for record in self.records:
            if record.tool_call_id == tool_call_id:
                return record
        return None
    
    def get_messages(self) -> List[Dict[str, Any]]:
        """
        Get all tool call results as messages for LLM.
        
        Returns:
            List of message dicts with role='tool'
        """
        messages = []
        for record in self.records:
            msg = record.to_message()
            if msg:  # Skip dropped records
                messages.append(msg)
        return messages
    
    def truncate(self, target_tokens: int) -> int:
        """
        Apply truncation strategies to reach target token count.

        Args:
            target_tokens: Target maximum tokens

        Returns:
            Number of tokens removed
        """
        initial_tokens = self._current_tokens

        # Strategy 1: Drop oldest LOW priority records
        tokens_removed = self._drop_by_priority("LOW", target_tokens)
        if self._current_tokens <= target_tokens:
            return initial_tokens - self._current_tokens

        # Strategy 2: Drop oldest MEDIUM priority records
        tokens_removed += self._drop_by_priority("MEDIUM", target_tokens)
        if self._current_tokens <= target_tokens:
            return initial_tokens - self._current_tokens

        # Strategy 3: Summarize groups of similar calls
        tokens_removed += self._summarize_groups(target_tokens)
        if self._current_tokens <= target_tokens:
            return initial_tokens - self._current_tokens

        # Strategy 4: Reduce to metadata-only (oldest first)
        tokens_removed += self._reduce_to_metadata(target_tokens)
        if self._current_tokens <= target_tokens:
            return initial_tokens - self._current_tokens

        # Strategy 5: Reduce to status-only (oldest first)
        tokens_removed += self._reduce_to_status(target_tokens)
        if self._current_tokens <= target_tokens:
            return initial_tokens - self._current_tokens

        # Strategy 6: Drop oldest records entirely (regardless of priority)
        tokens_removed += self._drop_oldest(target_tokens)

        return initial_tokens - self._current_tokens

    def _drop_by_priority(self, priority: str, target_tokens: int) -> int:
        """Drop oldest records with specified priority."""
        tokens_removed = 0

        # Collect records to potentially remove (in order from oldest)
        candidates = []
        for record in self.records:
            if record.priority == priority and record.strategy != TruncationStrategy.DROPPED:
                candidates.append(record)
        
        # Drop records one by one until we're under target
        for record in candidates:
            if self._current_tokens - tokens_removed <= target_tokens:
                break
            self.records.remove(record)
            record.strategy = TruncationStrategy.DROPPED
            tokens_removed += record.tokens
            self._current_tokens -= record.tokens

        return tokens_removed
    
    def _summarize_groups(self, target_tokens: int) -> int:
        """Group similar tool calls and summarize them."""
        # Group by tool name
        groups: Dict[str, ToolCallGroup] = {}
        for record in self.records:
            if record.strategy != TruncationStrategy.FULL:
                continue  # Already processed
            if record.name not in groups:
                groups[record.name] = ToolCallGroup(tool_name=record.name)
            groups[record.name].add(record)
        
        tokens_removed = 0
        
        # Summarize groups with 3+ calls (oldest first)
        for tool_name, group in sorted(groups.items(), 
                                        key=lambda x: -len(x[1].calls)):
            if len(group.calls) >= 3:
                # Mark individual calls as summarized
                for record in group.calls[:-2]:  # Keep last 2 full
                    tokens_removed += record.tokens - 50  # Approximate summary size
                    record.strategy = TruncationStrategy.SUMMARIZED
                
                if self._current_tokens - tokens_removed <= target_tokens:
                    break
        
        self._current_tokens -= tokens_removed
        return tokens_removed
    
    def _reduce_to_metadata(self, target_tokens: int) -> int:
        """Reduce oldest records to metadata-only."""
        tokens_removed = 0
        
        for record in list(self.records):
            if record.strategy == TruncationStrategy.FULL:
                old_tokens = record.tokens
                record.strategy = TruncationStrategy.METADATA_ONLY
                new_tokens = len(record._metadata_summary()) // 4
                tokens_removed += old_tokens - new_tokens
                record.tokens = new_tokens
                
                if self._current_tokens - tokens_removed <= target_tokens:
                    break
        
        self._current_tokens -= tokens_removed
        return tokens_removed
    
    def _reduce_to_status(self, target_tokens: int) -> int:
        """Reduce oldest records to status-only."""
        tokens_removed = 0
        
        for record in list(self.records):
            if record.strategy in (TruncationStrategy.FULL, TruncationStrategy.METADATA_ONLY):
                old_tokens = record.tokens
                record.strategy = TruncationStrategy.STATUS_ONLY
                new_tokens = len(record._status_summary()) // 4
                tokens_removed += old_tokens - new_tokens
                record.tokens = new_tokens
                
                if self._current_tokens - tokens_removed <= target_tokens:
                    break
        
        self._current_tokens -= tokens_removed
        return tokens_removed
    
    def _drop_oldest(self, target_tokens: int) -> int:
        """Drop oldest records entirely."""
        tokens_removed = 0
        
        while self.records and self._current_tokens - tokens_removed > target_tokens:
            oldest = self.records.popleft()
            tokens_removed += oldest.tokens
            self._current_tokens -= oldest.tokens
        
        return tokens_removed
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        by_priority = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_strategy = {}
        
        for record in self.records:
            by_priority[record.priority] = by_priority.get(record.priority, 0) + 1
            strat_key = record.strategy.value
            by_strategy[strat_key] = by_strategy.get(strat_key, 0) + 1
        
        return {
            "total_records": len(self.records),
            "total_tokens": self._current_tokens,
            "by_priority": by_priority,
            "by_strategy": by_strategy,
        }
    
    def clear(self) -> None:
        """Clear all records."""
        self.records.clear()
        self._current_tokens = 0
    
    def summary(self) -> str:
        """Get human-readable summary."""
        stats = self.get_statistics()
        lines = [
            f"Tool Output Buffer: {stats['total_records']} records, {stats['total_tokens']:,} tokens",
            "",
            "By Priority:",
        ]
        for priority, count in stats['by_priority'].items():
            if count > 0:
                lines.append(f"  {priority}: {count}")
        
        if stats['by_strategy']:
            lines.append("")
            lines.append("By Truncation Strategy:")
            for strategy, count in stats['by_strategy'].items():
                lines.append(f"  {strategy}: {count}")
        
        return "\n".join(lines)
