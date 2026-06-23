"""
Context Manager - Orchestrates all context management components.

Provides a unified interface for:
- Token budget tracking
- Tool output buffering
- Conversation summarization
- Cache-stable prompt assembly
"""

import logging
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass

from .budget import ContextBudget
from .tool_buffer import ToolOutputBuffer
from .summarizer import ConversationSummarizer, ConversationTurn
from .block_buffer import BlockBuffer
from .config import get_context_setting


# Get logger for this module
logger = logging.getLogger(__name__)


@dataclass
class PromptSections:
    """
    Token counts for each section of the assembled prompt.

    Used for tracking cache-stable vs cache-volatile portions.
    """
    system: int = 0
    summary: int = 0
    checkpoint: int = 0
    memories: int = 0
    tool_buffer: int = 0
    conversation: int = 0
    current_query: int = 0

    @property
    def total(self) -> int:
        """Total tokens across all sections."""
        return (
            self.system + self.summary + self.checkpoint +
            self.memories + self.tool_buffer + self.conversation +
            self.current_query
        )

    @property
    def cache_stable(self) -> int:
        """Tokens in cache-stable sections (system, summary, checkpoint)."""
        return self.system + self.summary + self.checkpoint

    @property
    def cache_volatile(self) -> int:
        """Tokens in cache-volatile sections (rest)."""
        return self.total - self.cache_stable


@dataclass
class AssembledPrompt:
    """
    Result of ContextManager.assemble_prompt().

    Contains both the messages for the LLM API and the updated
    conversation history with summarization applied.

    Attributes:
        messages: List of message dicts to send to LLM API
        conversation_history: Updated conversation history with summaries
    """
    messages: List[Dict[str, Any]]
    conversation_history: List[Dict[str, Any]]


class ContextManager:
    """
    Orchestrates context management for LLM agent loops.
    
    Manages:
    - Token budget tracking across prompt sections
    - Tool output buffering with intelligent truncation
    - Conversation summarization for long histories
    - Cache-stable prompt assembly
    
    Usage:
        context = ContextManager(budget, memory_store)
        
        # Before each LLM call
        messages = context.assemble_prompt(
            system_prompt=SYSTEM_PROMPT,
            conversation_history=history,
            checkpoint=checkpoint,
            current_task=task,
            relevant_memories=memories
        )
        
        # After tool execution
        context.add_tool_result(name, args, result)
        
        # Check if truncation needed
        if context.needs_truncation():
            context.truncate()
    """
    
    def __init__(self,
                 budget: Optional[ContextBudget] = None,
                 memory_store=None,  # MemoryStore type (avoid circular import)
                 tool_buffer: Optional[ToolOutputBuffer] = None,
                 summarizer: Optional[ConversationSummarizer] = None,
                 block_buffer: Optional[BlockBuffer] = None,
                 explorer=None,
                 summarizer_agent=None):  # CodeExplorer type (avoid circular import)
        """
        Initialize context manager.

        Args:
            budget: Token budget configuration
            memory_store: Memory store for semantic retrieval
            tool_buffer: Tool output buffer (created if None)
            summarizer: Conversation summarizer (created if None)
            block_buffer: Block buffer for tool-call-aware conversation (created if None)
            explorer: CodeExplorer for file listing (needed for file tracking)
            summarizer_agent: Optional SummarizerAgent for LLM-based summarization
        """
        self.budget = budget or ContextBudget()
        self.memory_store = memory_store
        self.tool_buffer = tool_buffer or ToolOutputBuffer(
            max_tokens=self.budget.tool_buffer_reserve
        )
        self.summarizer = summarizer or ConversationSummarizer()
        block_buffer_max_tokens = get_context_setting(
            "block_buffer",
            "max_tokens",
            default=int(
                self.budget.get_section_budget("working")
                * get_context_setting("block_buffer", "max_tokens_ratio_of_working_buffer", default=0.5)
            ),
        )
        self.block_buffer = block_buffer or BlockBuffer(
            max_raw_blocks=get_context_setting("block_buffer", "max_raw_blocks", default=15),
            max_tokens=block_buffer_max_tokens,
        )
        self.explorer = explorer
        self.summarizer_agent = summarizer_agent
        self._plan_manager = None  # Set via set_plan_manager()

        # Current state
        self._session_summary: str = ""
        self._checkpoint_summary: str = ""
        self._current_sections = PromptSections()
        self._files_analyzed: set = set()
        self._agent_state_provider: Callable[[], str] | None = None

    def set_plan_manager(self, plan_manager) -> None:
        """Set the plan manager for plan-aware summarization."""
        self._plan_manager = plan_manager

    def set_agent_state_provider(self, provider: Callable[[], str] | None) -> None:
        """Set a callable that renders the current agent state for prompt inclusion."""
        self._agent_state_provider = provider
    
    def set_session_summary(self, summary: str) -> None:
        """Set the session summary (updated periodically)."""
        self._session_summary = summary

    def set_checkpoint_summary(self, summary: str) -> None:
        """Set the checkpoint summary (updated from checkpoint)."""
        self._checkpoint_summary = summary

    def mark_file_analyzed(self, file_path: str) -> None:
        """Mark a file as analyzed."""
        self._files_analyzed.add(file_path)

    def get_files_analyzed(self) -> set:
        """Get set of analyzed files."""
        return self._files_analyzed.copy()

    def get_remaining_files(self, glob_pattern: Optional[str] = None, limit: int = 20) -> List[str]:
        """Get list of files not yet analyzed."""
        if not self.explorer:
            return []
        
        all_files = set(self.explorer.list_files())
        remaining = all_files - self._files_analyzed
        
        if glob_pattern:
            import fnmatch
            remaining = [f for f in remaining if fnmatch.fnmatch(f, glob_pattern)]
        
        return sorted(list(remaining))[:limit]

    def get_analysis_progress(self) -> Dict[str, Any]:
        """Get analysis progress summary."""
        if not self.explorer:
            return {"examined": 0, "remaining": 0, "total": 0}
        
        all_files = set(self.explorer.list_files())
        examined = len(self._files_analyzed)
        remaining = len(all_files - self._files_analyzed)
        total = len(all_files)
        
        return {
            "examined": examined,
            "remaining": remaining,
            "total": total,
            "percent": (examined * 100 // total) if total > 0 else 0
        }

    def _format_files_section(self) -> str:
        """Format file tracking section for prompt."""
        progress = self.get_analysis_progress()
        
        lines = [
            f"[FILES]",
            f"Examined: {progress['examined']}/{progress['total']} files ({progress['percent']}%)",
            f"Remaining: {progress['remaining']} files",
        ]
        
        # Show sample of remaining files
        remaining = self.get_remaining_files(limit=5)
        if remaining:
            lines.append("")
            lines.append("Sample remaining files:")
            for f in remaining:
                lines.append(f"  - {f}")
            if progress['remaining'] > 5:
                lines.append(f"  ... and {progress['remaining'] - 5} more")
        
        return "\n".join(lines)

    def _format_agent_state_section(self) -> str:
        """Format agent state for inclusion in the system prompt."""
        if self._agent_state_provider is None:
            return ""
        try:
            content = self._agent_state_provider()
        except Exception as exc:
            logger.warning(f"Failed to render agent state for prompt: {exc}")
            return ""
        if not content:
            return ""
        return content
    
    def add_tool_result(self, name: str, arguments: Dict[str, Any], result: str, tool_call_id: str = "") -> None:
        """
        Record a tool execution result.

        Args:
            name: Tool name
            arguments: Tool arguments
            result: Tool result string
            tool_call_id: Unique tool call ID
        """
        self.tool_buffer.add(name, arguments, result, tool_call_id=tool_call_id)
        logger.debug(f"Tool buffer: added {name} ({len(result)} chars)")
    
    def assemble_prompt(self,
                        system_prompt: str,
                        conversation_history: List[Dict[str, Any]],
                        checkpoint: Optional[Any] = None,
                        current_task: str = "",
                        relevant_memories: Optional[List[Any]] = None,
                        plan: Optional[Any] = None) -> AssembledPrompt:
        """
        Assemble a cache-stable prompt from all components.

        Prompt structure (stable → volatile):
        1. System prompt (never changes) - CACHED
        2. Session summary (changes every 10-20 turns) - SEMI-CACHED
        3. Checkpoint state (changes every 5-10 turns) - SEMI-CACHED
        4. Active plan (changes per action) - SEMI-CACHED
        5. Relevant memories (semantic retrieval) - VOLATILE
        6. Tool output buffer (recent tool calls) - VOLATILE
        7. Conversation history (sliding window) - VOLATILE
        8. Current query (new each turn) - VOLATILE

        Args:
            system_prompt: System prompt (stable)
            conversation_history: Raw conversation messages
            checkpoint: Optional AnalysisCheckpoint
            current_task: Current task/query
            relevant_memories: Optional pre-fetched memories from MemoryStore
            plan: Optional Plan from PlanManager

        Returns:
            AssembledPrompt with messages for LLM API and updated conversation history
        """
        messages = []
        sections = PromptSections()
        system_sections: List[str] = []

        # 1. System prompt (most stable - cached)
        system_sections.append(system_prompt)
        sections.system = len(system_prompt) // 4

        # 2. Session summary (semi-stable)
        if self._session_summary:
            system_sections.append(f"[SESSION SUMMARY]\n{self._session_summary}")
            sections.summary = len(self._session_summary) // 4 + 20

        # 3. Checkpoint state (semi-stable)
        if checkpoint:
            checkpoint_content = self._format_checkpoint(checkpoint)
            system_sections.append(f"[CHECKPOINT]\n{checkpoint_content}")
            sections.checkpoint = len(checkpoint_content) // 4 + 20

        # 4. Active plan (semi-stable - changes per action)
        if plan:
            from ...services.planning.prompts import format_plan_for_prompt

            plan_content = format_plan_for_prompt(plan)
            if plan_content:
                system_sections.append(plan_content)  # format_plan_for_prompt already includes [ACTIVE PLAN]

        agent_state_content = self._format_agent_state_section()
        if agent_state_content:
            system_sections.append(agent_state_content)

        # 4b. File tracking (semi-stable - changes as files are examined)
        if self.explorer:
            files_content = self._format_files_section()
            system_sections.append(files_content)

        # 5. Relevant memories (volatile - changes per query)
        if relevant_memories:
            memories_content = self._format_memories(relevant_memories)
            system_sections.append(f"[RELEVANT FINDINGS]\n{memories_content}")
            sections.memories = len(memories_content) // 4 + 20
        elif self.memory_store:
            # Auto-fetch relevant memories if current_task provided
            if current_task:
                memories = self.memory_store.search_memories(
                    current_task, top_k=5
                )
                if memories:
                    memories_content = self._format_memories(memories)
                    system_sections.append(f"[RELEVANT FINDINGS]\n{memories_content}")
                    sections.memories = len(memories_content) // 4 + 20

        # 5. Tool output buffer (volatile - truncated as needed)
        # Note: We don't include tool_buffer messages in the prompt because:
        # - Tool results are already in conversation_history with proper tool_call_id
        # - OpenRouter/Azure requires specific tool_call_id format
        # - tool_buffer is used for tracking/truncation decisions only
        sections.tool_buffer = self.tool_buffer.current_tokens  # For tracking only, not in prompt

        # 6. Conversation history (volatile - block-based with summarization)
        # Clear block buffer and rebuild from conversation history
        self.block_buffer.clear()

        # Add messages to block buffer (groups tool_calls with responses)
        for msg in conversation_history:
            # Skip consolidated summary messages - they're already in block_buffer's summary system
            if msg.get("role") == "system" and "[CONVERSATION SUMMARY]" in msg.get("content", ""):
                continue

            # Apply truncation from tool_buffer if it's a tool response
            if msg.get("role") == "tool" and "tool_call_id" in msg:
                record = self.tool_buffer.get_record_by_id(msg["tool_call_id"])
                if record:
                    # Create a copy with truncated content
                    msg_to_add = msg.copy()
                    msg_to_add["content"] = record.get_truncated_content()
                    self.block_buffer.add_message(msg_to_add)
                    continue

            self.block_buffer.add_message(msg)

        # Safety check: Ensure tool responses have their assistant message in the same block
        # If a tool response is orphaned (assistant was summarized), we need to handle it
        self._ensure_tool_call_pairing()

        # Check if aggressive truncation needed (over hard limit)
        if self.budget.at_hard_limit() or self.block_buffer.needs_aggressive_truncation():
            # Calculate target tokens for conversation section
            conv_target = self.budget.get_target_tokens("working")
            tokens_freed = self.block_buffer.truncate_to_budget(conv_target)
            logger.warning(f"Aggressive block truncation: freed {tokens_freed} tokens")

        # Check if summarization needed
        elif self.block_buffer.needs_summarization():
            # Only summarize if we have at least 5 raw blocks (batch processing)
            raw_block_count = self.block_buffer.raw_block_count
            if raw_block_count >= 5:
                plan = None
                # Try to get plan from plan_manager if available
                if hasattr(self, '_plan_manager'):
                    plan = self._plan_manager.active_plan

                # Summarize in batches of 5 using LLM agent if available
                blocks_summarized = self.block_buffer.summarize_oldest_blocks(
                    num_blocks=5,
                    summarizer_agent=self.summarizer_agent,
                    plan=plan
                )
                if blocks_summarized > 0:
                    logger.info(f"Summarized {blocks_summarized} conversation blocks (batch of 5)")
            else:
                logger.debug(f"Waiting for more blocks to summarize: {raw_block_count}/5")

        # Get summarized conversation history (includes session + variable summary + raw blocks)
        summarized_history = self.block_buffer.get_summarized_conversation_history()

        conversation_messages = []
        for msg in summarized_history:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if content:
                    system_sections.append(content)
                continue
            conversation_messages.append(msg)

        if system_sections:
            messages.append({"role": "system", "content": "\n\n".join(system_sections)})

        # Add summarized history to messages
        messages.extend(conversation_messages)
        sections.conversation = self.block_buffer.current_tokens

        # 7. Current query (most volatile)
        if current_task:
            messages.append({"role": "user", "content": current_task})
            sections.current_query = len(current_task) // 4

        # Update budget tracking
        # Note: tool_buffer is tracked separately (not in actual prompt)
        self._current_sections = sections
        self.budget.update_usage(
            system_tokens=sections.system,
            summary_tokens=sections.summary,
            memories_tokens=sections.memories,
            tool_buffer_tokens=0,  # Not in prompt - tracked separately
            conversation_tokens=sections.conversation + sections.current_query
        )

        # Log actual prompt size (what's actually sent to LLM)
        actual_prompt_tokens = (
            sections.system +
            sections.summary +
            sections.checkpoint +
            sections.memories +
            sections.conversation +
            sections.current_query
        )
        logger.debug(f"Actual prompt tokens: {actual_prompt_tokens:,} (tool_buffer tracks {sections.tool_buffer:,} separately)")

        return AssembledPrompt(
            messages=messages,
            conversation_history=summarized_history
        )
    
    def _format_checkpoint(self, checkpoint) -> str:
        """Format checkpoint as prompt section."""
        lines = ["Analysis State:"]
        
        if hasattr(checkpoint, 'files_analyzed'):
            lines.append(f"  Files analyzed: {len(checkpoint.files_analyzed)}")
        if hasattr(checkpoint, 'files_remaining'):
            lines.append(f"  Files remaining: {len(checkpoint.files_remaining)}")
        if hasattr(checkpoint, 'key_behaviors'):
            lines.append(f"  Key behaviors: {len(checkpoint.key_behaviors)}")
        if hasattr(checkpoint, 'active_hypotheses'):
            lines.append(f"  Active hypotheses: {len(checkpoint.active_hypotheses)}")
        if hasattr(checkpoint, 'open_questions'):
            lines.append(f"  Open questions: {len(checkpoint.open_questions)}")
        
        if hasattr(checkpoint, 'next_task') and checkpoint.next_task:
            lines.append(f"\n  Next task: {checkpoint.next_task}")
        
        return "\n".join(lines)
    
    def _format_memories(self, memories: List[Any]) -> str:
        """Format retrieved memories as prompt section."""
        if not memories:
            return "  No relevant findings."
        
        lines = ["Retrieved findings:"]
        for i, mem in enumerate(memories[:5], 1):  # Limit to top 5
            if hasattr(mem, 'memory'):
                mem = mem.memory  # Unwrap RetrievalResult
            if hasattr(mem, 'get_display_content'):
                content = mem.get_display_content()
            else:
                content = str(mem)
            lines.append(f"  {i}. [{getattr(mem, 'category', '?')}] {content[:100]}...")
        
        if len(memories) > 5:
            lines.append(f"  ... and {len(memories) - 5} more")
        
        return "\n".join(lines)
    
    def _convert_to_turns(self, history: List[Dict[str, Any]]) -> List[ConversationTurn]:
        """Convert raw message history to ConversationTurn objects."""
        turns = []
        for msg in history:
            role = msg.get("role", "unknown")
            content = msg.get("content") or ""  # Handle None content
            tool_call_id = msg.get("tool_call_id")  # For tool messages
            turns.append(ConversationTurn(
                role=role,
                content=content,
                tool_call_id=tool_call_id
            ))
        return turns
    
    def needs_truncation(self) -> bool:
        """Check if context needs truncation."""
        return self.budget.needs_truncation()
    
    def needs_summarization(self) -> bool:
        """Check if context needs summarization."""
        return self.budget.needs_summarization()
    
    def truncate(self, target_tokens: Optional[int] = None) -> int:
        """
        Apply truncation to reduce token usage.

        Args:
            target_tokens: Optional target (uses budget target if None)

        Returns:
            Number of tokens removed
        """
        tokens_removed = 0

        # If at hard limit, use aggressive truncation on BOTH buffers
        if self.budget.at_hard_limit():
            # Aggressive tool buffer truncation (50% of budget)
            aggressive_target = self.budget.get_target_tokens("tool_buffer")
            tokens_removed += self.tool_buffer.truncate(aggressive_target)

            # Always truncate block buffer at hard limit
            conv_target = self.budget.get_target_tokens("working")
            tokens_removed += self.block_buffer.truncate_to_budget(conv_target)

            logger.warning(f"Hard limit truncation: removed {tokens_removed} tokens total")
        else:
            # Normal truncation
            if target_tokens is None:
                target_tokens = self.budget.get_target_tokens("tool_buffer")
            tokens_removed = self.tool_buffer.truncate(target_tokens)
            logger.info(f"Context truncation: removed {tokens_removed} tokens from tool buffer")

        return tokens_removed

    def truncate_to_plan_boundary(self) -> int:
        """
        Truncate context at plan completion boundary.

        More aggressive than normal truncation since we're starting a new phase.
        Keeps only:
        - System prompt
        - Session summary
        - Last N tool calls (recent context)
        - Key findings from completed plan (via memories)

        Returns:
            Number of tokens freed
        """
        tokens_removed = 0

        # Aggressive tool buffer truncation - keep only 25% of reserve
        target_tokens = self.budget.tool_buffer_reserve // 4
        tokens_removed += self.tool_buffer.truncate(target_tokens)
        logger.info(f"Plan boundary truncation (tool buffer): removed {tokens_removed} tokens")

        # Summarize all conversation blocks except last 2
        blocks_to_summarize = max(0, len(self.block_buffer.blocks) - 2)
        if blocks_to_summarize > 0:
            summarized = self.block_buffer.summarize_oldest_blocks(num_blocks=blocks_to_summarize)
            logger.info(f"Plan boundary truncation: summarized {summarized} conversation blocks")

        return tokens_removed

    def summarize_conversation_history(
        self,
        conversation_history: List[Dict[str, Any]],
        *,
        fallback_summary: str = "",
        preserve_recent_blocks: int = 2,
        summarizer_agent: Any = None,
        plan: Any = None,
    ) -> List[Dict[str, Any]]:
        """
        Summarize conversation history through the shared context backend.

        Rebuilds the tool-call-aware block buffer, summarizes older blocks into
        the variable/session summary mechanism, and preserves the most recent
        blocks raw so tool-call pairing and recent context remain intact.
        """
        self.block_buffer.clear()
        for message in conversation_history:
            self.block_buffer.add_message(message)

        blocks = list(self.block_buffer.blocks)
        if not blocks:
            if fallback_summary:
                self.block_buffer.add_to_variable_summary(
                    fallback_summary,
                    summarizer_agent=summarizer_agent,
                )
            return self.block_buffer.get_summarized_conversation_history()

        keep_count = max(0, min(preserve_recent_blocks, len(blocks)))
        blocks_to_summarize = blocks[:-keep_count] if keep_count else blocks
        blocks_to_keep = blocks[-keep_count:] if keep_count else []

        summary_text = ""
        if blocks_to_summarize:
            if summarizer_agent is not None:
                batch_summary = summarizer_agent.summarize_blocks(
                    blocks_to_summarize,
                    plan=plan,
                )
                summary_text = batch_summary.chronological_summary
            else:
                turns = [
                    turn
                    for block in blocks_to_summarize
                    for turn in self._convert_to_turns(block.messages)
                ]
                summary_text = self.summarizer.summarize_turns(turns).summary

        if not summary_text and fallback_summary:
            summary_text = fallback_summary

        self.block_buffer.clear()
        if summary_text:
            self.block_buffer.add_to_variable_summary(
                summary_text,
                summarizer_agent=summarizer_agent,
            )
        for block in blocks_to_keep:
            for message in block.messages:
                self.block_buffer.add_message(message)

        return self.block_buffer.get_summarized_conversation_history()

    def _ensure_tool_call_pairing(self) -> None:
        """
        Ensure tool responses are paired with their assistant messages.

        The LLM API requires that every tool response message must be preceded
        by an assistant message with corresponding tool_calls. This method checks
        for orphaned tool responses and logs a warning if found.

        Note: This is a safety check - the main fix is in summarize_oldest_blocks()
        which prevents blocks with tool responses from being summarized.
        """
        # Collect all tool_call_ids from assistant messages
        assistant_tool_ids = set()
        for block in self.block_buffer.blocks:
            for msg in block.messages:
                tool_calls = msg.get("tool_calls") or []
                if msg.get("role") == "assistant" and tool_calls:
                    for tc in tool_calls:
                        if isinstance(tc, dict):
                            assistant_tool_ids.add(tc.get("id", ""))
                        elif hasattr(tc, 'id'):
                            assistant_tool_ids.add(tc.id)

        # Check for orphaned tool responses
        for block in self.block_buffer.blocks:
            for msg in block.messages:
                if msg.get("role") == "tool" and "tool_call_id" in msg:
                    tool_call_id = msg["tool_call_id"]
                    if tool_call_id not in assistant_tool_ids:
                        logger.warning(
                            f"Orphaned tool response: tool_call_id={tool_call_id} "
                            f"has no matching assistant message with tool_calls"
                        )

    def on_plan_completed(self, plan: Any = None) -> int:
        """
        Called when a plan completes. Apply opportunistic truncation.

        At plan completion, old tool results are less relevant since we're
        starting a new phase of analysis.

        Args:
            plan: The completed plan (optional, for logging)

        Returns:
            Number of tokens freed
        """
        plan_info = f" (plan: {plan.goal[:40]}...)" if plan and hasattr(plan, 'goal') else ""
        logger.info(f"Plan completed{plan_info} - applying opportunistic truncation")

        tokens_freed = self.truncate_to_plan_boundary()

        logger.info(f"Plan completion truncation: freed {tokens_freed} tokens total")
        return tokens_freed

    def get_statistics(self) -> Dict[str, Any]:
        """Get context management statistics."""
        return {
            "budget": {
                "total": self.budget.max_tokens,
                "current": self.budget.current_usage,
                "ratio": self.budget.usage_ratio,
            },
            "sections": {
                "system": self._current_sections.system,
                "summary": self._current_sections.summary,
                "checkpoint": self._current_sections.checkpoint,
                "memories": self._current_sections.memories,
                "tool_buffer": self._current_sections.tool_buffer,
                "conversation": self._current_sections.conversation,
                "current_query": self._current_sections.current_query,
                "total": self._current_sections.total,
                "cache_stable": self._current_sections.cache_stable,
                "cache_volatile": self._current_sections.cache_volatile,
            },
            "tool_buffer": self.tool_buffer.get_statistics(),
            "block_buffer": self.block_buffer.get_statistics(),
        }

    def summary(self) -> str:
        """Get human-readable context summary."""
        block_stats = self.block_buffer.get_statistics()
        lines = [
            "Context Manager Status:",
            self.budget.summary(),
            "",
            f"Cache-stable: {self._current_sections.cache_stable:,} tokens",
            f"Cache-volatile: {self._current_sections.cache_volatile:,} tokens",
            "",
            "Tool Buffer:",
            self.tool_buffer.summary(),
            "",
            "Block Buffer (Conversation):",
            f"  Total blocks: {block_stats['total_blocks']}",
            f"  Raw blocks: {block_stats['raw_blocks']}",
            f"  Summarized blocks: {block_stats['summarized_blocks']}",
            f"  Block tokens: {block_stats['total_tokens']:,}",
        ]
        return "\n".join(lines)

    def reset(self) -> None:
        """Reset context state (for new session)."""
        self._session_summary = ""
        self._checkpoint_summary = ""
        self._current_sections = PromptSections()
        self.tool_buffer.clear()
        self.block_buffer.clear()
        self.budget.reset()
