"""
Summarizer Agent - LLM-based conversation summarization.

This agent:
- Takes raw conversation blocks as input
- Uses LLM to generate meaningful chronological summaries
- Returns structured summary for context management
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

from .config import get_context_setting


logger = logging.getLogger(__name__)


@dataclass
class SummarizedBlock:
    """
    Represents a summarized conversation block.
    
    Attributes:
        tool_name: Name of the tool called
        tool_args: Tool arguments (abbreviated)
        result_summary: Brief summary of the result
        key_finding: Optional key finding to store as memory
        memory_category: Category for memory (function, behavior, etc.)
        memory_priority: Priority level for memory
    """
    tool_name: str
    tool_args: str
    result_summary: str
    key_finding: Optional[str] = None
    memory_category: Optional[str] = None
    memory_priority: Optional[str] = None


@dataclass
class BatchSummary:
    """
    Summary of a batch of conversation blocks.

    Attributes:
        summary_by_action: Legacy grouped summary data when returned by the model
        chronological_summary: Fallback chronological summary (for compatibility)
        key_findings: List of important findings extracted from the summary
        files_examined: List of files that were read
        total_blocks: Number of blocks summarized
    """
    summary_by_action: List[Dict[str, Any]]
    chronological_summary: str
    key_findings: List[Dict[str, Any]]
    files_examined: List[str]
    total_blocks: int


class SummarizerAgent:
    """
    LLM-based agent for generating meaningful conversation summaries.
    
    Usage:
        summarizer = SummarizerAgent(api_key, memory_store)
        summary = summarizer.summarize_blocks(blocks)
        
        # Summary includes:
        # - chronological_summary: Text summary for context
        # - key_findings: Extracted findings from the summary
        # - files_examined: Files that were analyzed
    """
    
    SYSTEM_PROMPT = """You are a conversation summarizer for a source code analysis agent.

Your task is to summarize a batch of tool calls and their results as plain chronological analysis notes.

INPUT FORMAT:
You will receive:
1. A list of tool calls with their arguments and results

OUTPUT FORMAT:
You MUST respond with valid JSON in this exact format:
{
    "chronological_summary": [
        "Examined sekurlsa module implementation and identified credential dumping functions including MSV1_0, WDigest, and Kerberos extraction methods.",
        "Reviewed golden ticket implementation and Kerberos credential caching behavior."
    ],
    "key_findings": [
        {
            "key": "sekurlsa_credential_dumping",
            "value": "Detailed description",
            "category": "behavior",
            "priority": "CRITICAL"
        }
    ],
    "files_examined": ["kuhl_m_sekurlsa.c", "kuhl_m_kerberos.c"]
}

OUTPUT REQUIREMENTS:
1. CHRONOLOGICAL SUMMARY:
   - Provide concise narrative summary items in the order the work was performed
   - Do not tag or group entries by plan action
   - Focus on what was done and what was discovered

2. KEY FINDINGS: Extract important discoveries from the summarized work

3. FILES EXAMINED: List files that were read

GUIDELINES:
- Write summaries as concise narrative paragraphs, NOT as tool call listings
- Focus on what was discovered/analyzed, not which tools were called
- Keep the summary as a plain chronological chain of analysis steps
- Be specific about findings (function names, counts, key discoveries)
- Respond ONLY with JSON, no additional text

EXAMPLE OUTPUT:
{
    "chronological_summary": [
        "Examined sekurlsa module implementation and identified credential dumping functions including MSV1_0, WDigest, and Kerberos extraction methods."
    ],
    "key_findings": [...],
    "files_examined": ["kuhl_m_sekurlsa.c"]
}
"""

    META_SYSTEM_PROMPT = """You are a conversation summarizer for a source code analysis agent.

Your task is to consolidate two summaries into a single, coherent session summary:
1. Session Summary - Long-term findings accumulated across the entire session
2. Variable Summary - Recent conversation history that has grown large

INPUT FORMAT:
You will receive:
1. session_summary: Existing persistent session findings (may be empty initially)
2. variable_summary: Recent conversation history to merge into session summary
3. target_length: Target character count for the consolidated summary

OUTPUT FORMAT:
You MUST respond with valid JSON in this exact format:
{
    "consolidated_session_summary": "Unified summary combining both inputs, deduplicated and compressed"
}

OUTPUT REQUIREMENTS:
1. CONSOLIDATED SESSION SUMMARY:
   - Merge information from both session_summary and variable_summary
   - Remove duplicate information
   - Compress verbose descriptions while preserving key details
   - Focus on: WHAT WAS DONE and WHAT NEEDS TO BE DONE NEXT
   - Target length: approximately target_length characters
   - Write in a concise, narrative format

GUIDELINES:
- Preserve all unique technical information
- Eliminate redundancy between session and variable summaries
- Structure as: "Analyzed X, discovered Y. Next: Z"
- Be specific about completed work and remaining tasks
- Prioritize actionable information
- Respond ONLY with JSON, no additional text

EXAMPLE OUTPUT:
{
    "consolidated_session_summary": "Analyzed mimikatz source code: examined sekurlsa module (kuhl_m_sekurlsa.c) containing MSV1_0, WDigest, Kerberos credential extraction; reviewed kerberos module golden ticket implementation; studied mimidrv kernel driver for protected process access. Key findings: logonSessionData holds plaintext credentials, TGT fabrication uses krbtgt hash. Next: analyze dpapi module for credential decryption, review mimilib provider implementation, complete remaining 15 files in modules/ directory."
}
"""

    def __init__(
        self,
        api_key: str,
        memory_store=None,
        model: str = "gpt-4.1-mini",
        base_url: Optional[str] = None
    ):
        """
        Initialize summarizer agent.
        
        Works with any LLM model (OpenAI, OpenRouter, local models, etc.)
        
        Args:
            api_key: OpenAI API key
            memory_store: Optional memory store reference (not used by summarizer output)
            model: LLM model to use
            base_url: Optional base URL for API (e.g., OpenRouter)
        """
        self.api_key = api_key
        self.memory_store = memory_store
        self.model = model
        self.summary_target_chars = (
            get_context_setting("summarizer", "max_summary_tokens", default=3000) * 4
        )
        
        # Auto-detect OpenRouter from API key prefix
        if base_url is None and api_key.startswith("sk-or-"):
            base_url = "https://openrouter.ai/api/v1"

        from openai import OpenAI

        self.client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
        
        logger.info(f"SummarizerAgent initialized with model={model}")
    
    def summarize_blocks(self, blocks: List[Any], plan: Any = None) -> BatchSummary:
        """
        Summarize a batch of conversation blocks using LLM.

        Args:
            blocks: List of ConversationBlock objects to summarize
            plan: Optional plan object (ignored for variable-summary generation)

        Returns:
            BatchSummary with chronological summary and extracted findings
        """
        # Convert blocks to LLM-friendly format
        block_data = self._blocks_to_input(blocks)

        # Call LLM to generate summary
        summary_json = self._call_llm(block_data, plan)

        # Parse and validate response
        batch_summary = self._parse_summary(summary_json)

        return batch_summary

    def meta_summarize(self, session_summary: str, variable_summary: str, target_length: int = 3500) -> str:
        """
        Consolidate session and variable summaries into a unified session summary.

        This is called when variable_summary reaches its threshold and needs to be
        merged into the persistent session_summary.

        Args:
            session_summary: Existing persistent session findings (may be empty)
            variable_summary: Recent conversation history to merge
            target_length: Target character count for consolidated summary

        Returns:
            Consolidated session summary string
        """
        # Build user message with both summaries
        user_content = f"""SESSION SUMMARY ({len(session_summary)} chars):
{session_summary if session_summary else "(empty)"}

VARIABLE SUMMARY ({len(variable_summary)} chars):
{variable_summary}

TARGET LENGTH: {target_length} characters

Please consolidate these into a unified session summary close to the target length.
Do not cut off text mid-sentence; rewrite/compress naturally instead."""

        messages = [
            {"role": "system", "content": self.META_SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

        try:
            logger.debug(f"Calling LLM for meta-summarization (model={self.model})...")
            logger.debug(f"Input size: {sum(len(m['content']) for m in messages)} chars")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3
            )

            logger.debug(f"LLM meta-summary response: choices={len(response.choices) if response else 'N/A'}")

            if response is None or not response.choices or response.choices[0].message is None:
                logger.warning("LLM meta-summary returned invalid response, using fallback")
                return self._fallback_meta_summary(session_summary, variable_summary)

            content = response.choices[0].message.content

            if not content:
                logger.warning("LLM meta-summary returned empty content")
                return self._fallback_meta_summary(session_summary, variable_summary)

            logger.debug(f"LLM meta-summary received {len(content)} chars")

            # Parse JSON response
            return self._parse_meta_summary(content)

        except Exception as e:
            logger.error(f"LLM meta-summarization failed: {e}")
            return self._fallback_meta_summary(session_summary, variable_summary)

    def _parse_meta_summary(self, content: str) -> str:
        """Parse LLM meta-summary response."""
        json_content = self._extract_json(content)

        try:
            data = json.loads(json_content)
            consolidated = data.get("consolidated_session_summary", "")

            if consolidated:
                return consolidated
            else:
                logger.warning("No consolidated summary in meta-summary response")
                return content

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse meta-summary JSON: {e}")
            return content

    def _fallback_meta_summary(self, session_summary: str, variable_summary: str) -> str:
        """Generate fallback summary if LLM fails."""
        # Simple concatenation with deduplication attempt
        if not session_summary:
            return variable_summary
        if not variable_summary:
            return session_summary

        return f"{session_summary}\n\n[Recent Additions]\n{variable_summary}"

    def _blocks_to_input(self, blocks: List[Any]) -> List[Dict[str, Any]]:
        """Convert ConversationBlock objects to LLM input format."""
        block_data = []
        
        for i, block in enumerate(blocks):
            block_info = {
                "block_index": i,
                "tool_calls": [],
                "tool_responses": []
            }
            
            for msg in block.messages:
                role = msg.get("role")
                
                tool_calls = msg.get("tool_calls") or []
                if role == "assistant" and tool_calls:
                    for tc in tool_calls:
                        if isinstance(tc, dict):
                            block_info["tool_calls"].append({
                                "name": tc.get("function", {}).get("name", "unknown"),
                                "arguments": tc.get("function", {}).get("arguments", "{}")
                            })
                        elif hasattr(tc, 'function'):
                            block_info["tool_calls"].append({
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            })
                
                elif role == "tool":
                    content = msg.get("content", "")
                    block_info["tool_responses"].append({
                        "tool_call_id": msg.get("tool_call_id", ""),
                        "content": content
                    })
            
            block_data.append(block_info)
        
        return block_data
    
    def _call_llm(self, block_data: List[Dict[str, Any]], plan: Any = None) -> str:
        """Call LLM to generate summary.
        
        Works with any LLM provider (OpenAI, OpenRouter, local models, etc.)
        Does not use response_format to ensure compatibility.
        
        Args:
            block_data: Tool call data to summarize
            plan: Optional plan object (unused)
        """
        # Build user message
        user_content = (
            f"Summarize the following {len(block_data)} tool call blocks into "
            f"approximately {self.summary_target_chars} characters or fewer. "
            "Do not cut off text mid-sentence; rewrite/compress naturally instead.\n\n"
        )
        user_content += json.dumps(block_data, indent=2, default=str)
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

        try:
            logger.debug(f"Calling LLM for summarization with {len(block_data)} blocks (model={self.model})...")
            logger.debug(f"Input size: {sum(len(m['content']) for m in messages)} chars")
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3
            )
            
            logger.debug(f"LLM response: choices={len(response.choices) if response and hasattr(response, 'choices') else 'N/A'}")

            # Check for valid response
            if response is None:
                logger.warning("LLM returned None response")
                return self._fallback_summary(block_data)

            if not response.choices or len(response.choices) == 0:
                logger.warning(f"LLM returned empty choices. Full response: {response}")
                return self._fallback_summary(block_data)

            if response.choices[0].message is None:
                logger.warning("LLM returned null message")
                return self._fallback_summary(block_data)

            content = response.choices[0].message.content
            
            if not content:
                logger.warning("LLM returned empty message content")
                return self._fallback_summary(block_data)
            
            logger.debug(f"LLM summarization received {len(content)} chars")
            return content

        except Exception as e:
            logger.error(f"LLM summarization failed: {e}")
            # Fallback to simple summary
            return self._fallback_summary(block_data)

    def _fallback_summary(self, block_data: List[Dict[str, Any]]) -> str:
        """Generate a simple fallback summary if LLM fails."""
        items = []
        for block in block_data:
            for tc in block.get("tool_calls", []):
                action = f"Called {tc['name']}()"
                result = "No result available"
                # Find matching tool response
                for tr in block.get("tool_responses", []):
                    content = tr.get("content", "")
                    result = self._summarize_fallback_result(content)
                items.append(f"• {action} → {result}")

        return json.dumps({
            "chronological_summary": items,
            "key_findings": [],
            "files_examined": []
        })
    
    def _parse_summary(self, summary_text: str) -> BatchSummary:
        """Parse LLM response into BatchSummary.

        Handles various response formats from different LLM providers.
        Supports both plain chronological output and older grouped-by-action output.
        """
        # Try to extract JSON from the response (some models add text before/after)
        json_content = self._extract_json(summary_text)

        try:
            data = json.loads(json_content)

            # Handle legacy grouped-by-action format by flattening to plain narrative items
            summary_by_action = data.get("summary_by_action", [])

            # Generate plain chronological summary from grouped output
            if summary_by_action:
                chronological_items = []
                for action_group in summary_by_action:
                    summary = action_group.get("summary", "")
                    if summary:
                        chronological_items.append(summary)

                chronological_summary = "\n".join(chronological_items)
            else:
                # Handle old format with chronological_summary
                chronological = data.get("chronological_summary", [])
                if isinstance(chronological, list) and len(chronological) > 0:
                    if isinstance(chronological[0], dict) and "action" in chronological[0]:
                        # Format: [{"action": "...", "result": "..."}, ...]
                        chronological_summary = "\n".join(
                            f"• {item.get('action', '')} → {item.get('result', '')}"
                            for item in chronological
                        )
                    else:
                        # Format: ["Called X - result", ...]
                        chronological_summary = "\n".join(str(item) for item in chronological)
                else:
                    chronological_summary = str(chronological) if chronological else ""

            return BatchSummary(
                summary_by_action=summary_by_action,
                chronological_summary=chronological_summary,
                key_findings=data.get("key_findings", []),
                files_examined=data.get("files_examined", []),
                total_blocks=len(data.get("summary_by_action", data.get("chronological_summary", [])))
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse summary JSON: {e}")
            # Return the raw text as chronological summary
            return BatchSummary(
                summary_by_action=[],
                chronological_summary=summary_text,
                key_findings=[],
                files_examined=[],
                total_blocks=0
            )

    def _summarize_fallback_result(self, content: str) -> str:
        normalized = " ".join(str(content or "").split())
        if len(normalized) <= 500:
            return normalized
        return f"tool response of {len(normalized)} chars"
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from text that may contain additional content.
        
        Handles cases where LLM adds text like 'Here is the summary:' before JSON.
        """
        # Try to find JSON object in the text
        start = text.find('{')
        end = text.rfind('}') + 1
        
        if start >= 0 and end > start:
            return text[start:end]
        
        # If no JSON found, return original text
        return text
    
