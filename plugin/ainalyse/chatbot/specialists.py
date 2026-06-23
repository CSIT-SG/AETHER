from __future__ import annotations

from typing import Any, Callable

from .chatbot_ida.bridge import ChatbotBackendBridge
from .specialist_registry import SpecialistAgentSpec
from .struct_agent import STRUCT_AGENT_ID, StructAgent


def build_default_specialist_bindings(
    bridge: ChatbotBackendBridge,
    handlers: dict[str, Callable[[Any, Any], None]],
) -> list[tuple[SpecialistAgentSpec, Callable[[], object], Callable[[Any, Any], None]]]:
    """
    Return default specialist bindings as:
      (spec, factory, runtime_message_handler)
    """
    return [
        (
            SpecialistAgentSpec(
                agent_id=STRUCT_AGENT_ID,
                capability="struct_operations",
                description="Specialist agent for struct creation and updates",
            ),
            lambda: StructAgent(bridge=bridge),
            handlers[STRUCT_AGENT_ID],
        ),
    ]
