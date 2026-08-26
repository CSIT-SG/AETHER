from pathlib import Path

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    get_local_variables,
)
from aether_backend.utils.get_rpc_service import AnyService
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_utils.get_content import get_content
from agents import Tool

from .adapter import EvidenceAdapter


class IDAEvidenceAdapter(EvidenceAdapter[AnyService]):
    """Grades the IDB file using the forwarded-RPC tools."""

    @property
    def system_prompt(self) -> str:
        return get_content(Path(__file__).parent, "evaluate_prompt.md")

    def build_tools(self) -> list[Tool]:
        return list(
            map(
                build_subagent_tool,
                [
                    get_data_at_address,
                    get_function_pseudocode,
                    get_local_variables,
                    get_functions_called_recursively,
                ],
            )
        )

    def run_context(self, evidence: AnyService) -> SubagentToolDependencies:
        return SubagentToolDependencies(evidence)

    def build_prompt(
        self,
        evidence: AnyService,
        criterion: str,
        description: str,
        rubric_name: str,
    ) -> str:
        return f"""# Rubric: {rubric_name}
## Description

{description}

## Criterion

{criterion}

Use the available evidence to determine whether this criterion is satisfied.
"""
