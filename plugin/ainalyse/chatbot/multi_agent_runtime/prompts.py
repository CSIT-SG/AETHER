from __future__ import annotations

from dataclasses import dataclass, field


SHARED_RULES_PROMPT = """Follow these rules:
1. Think step-by-step before calling tools.
2. Use the available tools deliberately and only when they advance the task.
3. Keep the current plan accurate as work progresses.
4. Use stored memory to preserve important findings and decisions."""


SHARED_MEMORY_PROMPT = """MEMORY:
You must use memory tools to preserve important findings, decisions, and intermediate results.
- Use `add_memory` when you discover something worth preserving for later retrieval.
- Use `search_memories` before repeating work that may already have been done.
- Store concise but meaningful findings with clear keys and categories."""


SHARED_PLANNING_PROMPT = """PLANNING:
You must keep a current plan while working on multi-step tasks.
- Use `create_plan` when starting a new multi-step goal.
- Use `update_plan` when work begins, completes, fails, or needs refinement.
- When updating an existing plan, use the exact `action_id` values shown in `[ACTIVE PLAN]`.
- Use `delete_plan` only when the current plan is complete or no longer relevant."""


SHARED_CONTEXT_PROMPT = """CONTEXT:
The runtime may provide summaries, checkpoint state, previous memories, and tool-call history.
- Use that context to avoid repeating work.
- Prefer incremental progress over restarting from scratch."""


DEFAULT_IDENTITY_PROMPT = "You are a general-purpose autonomous agent."
DEFAULT_CAPABILITY_PROMPT = "Use planning, memory, and the configured tools to make progress on the task."


@dataclass(slots=True)
class PromptConfig:
    identity: str = DEFAULT_IDENTITY_PROMPT
    capability: str = DEFAULT_CAPABILITY_PROMPT
    output_format: str = ""
    runtime_appendix: str = ""
    shared_rules: str = SHARED_RULES_PROMPT
    shared_memory: str = SHARED_MEMORY_PROMPT
    shared_planning: str = SHARED_PLANNING_PROMPT
    shared_context: str = SHARED_CONTEXT_PROMPT
    extra_sections: list[str] = field(default_factory=list)


class PromptComposer:
    def compose(self, config: PromptConfig) -> str:
        sections = [
            config.identity.strip(),
            config.shared_rules.strip(),
            config.shared_memory.strip(),
            config.shared_planning.strip(),
            config.shared_context.strip(),
            config.capability.strip(),
        ]
        if config.output_format.strip():
            sections.append(config.output_format.strip())
        for section in config.extra_sections:
            rendered = section.strip()
            if rendered:
                sections.append(rendered)
        if config.runtime_appendix.strip():
            sections.append(config.runtime_appendix.strip())
        return "\n\n".join(section for section in sections if section)
