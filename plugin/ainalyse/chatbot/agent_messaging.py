from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AgentMessageTopic(StrEnum):
    STRUCT_REQUEST = "struct_request"
    STRUCT_CONTINUE = "struct_continue"
    STRUCT_RESPONSE = "struct_response"
    AGENT_QUERY = "agent_query"
    AGENT_REPLY = "agent_reply"


class StructTaskStatus(StrEnum):
    CREATED = "created"
    MODIFIED = "modified"
    FAILED = "failed"


@dataclass(slots=True)
class StructRequestPayload:
    suggested_struct_name: str
    relevant_functions: list[str]
    context_description: str
    request_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.suggested_struct_name.strip():
            raise ValueError("suggested_struct_name cannot be empty")
        if not isinstance(self.relevant_functions, list):
            raise ValueError("relevant_functions must be a list")
        for value in self.relevant_functions:
            if not isinstance(value, str):
                raise ValueError("relevant_functions entries must be strings")
        if not self.context_description.strip():
            raise ValueError("context_description cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "suggested_struct_name": self.suggested_struct_name,
            "relevant_functions": list(self.relevant_functions),
            "context_description": self.context_description,
            "request_id": self.request_id,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "StructRequestPayload":
        instance = cls(
            suggested_struct_name=str(payload.get("suggested_struct_name", "")),
            relevant_functions=list(payload.get("relevant_functions") or []),
            context_description=str(payload.get("context_description", "")),
            request_id=str(payload.get("request_id", "")),
            metadata=dict(payload.get("metadata") or {}),
        )
        instance.validate()
        return instance


@dataclass(slots=True)
class StructResponsePayload:
    status: StructTaskStatus
    details: str
    requests_for_main_agent: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""

    def validate(self) -> None:
        if not isinstance(self.status, StructTaskStatus):
            raise ValueError("status must be a StructTaskStatus")
        if not self.details.strip():
            raise ValueError("details cannot be empty")
        for value in self.requests_for_main_agent:
            if not isinstance(value, str):
                raise ValueError("requests_for_main_agent entries must be strings")
        for value in self.warnings:
            if not isinstance(value, str):
                raise ValueError("warnings entries must be strings")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "status": self.status.value,
            "details": self.details,
            "requests_for_main_agent": list(self.requests_for_main_agent),
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
            "request_id": self.request_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "StructResponsePayload":
        status_raw = str(payload.get("status", "")).strip().lower()
        try:
            status = StructTaskStatus(status_raw)
        except ValueError as exc:
            raise ValueError(f"unsupported struct status '{status_raw}'") from exc
        instance = cls(
            status=status,
            details=str(payload.get("details", "")),
            requests_for_main_agent=list(payload.get("requests_for_main_agent") or []),
            warnings=list(payload.get("warnings") or []),
            metadata=dict(payload.get("metadata") or {}),
            request_id=str(payload.get("request_id", "")),
        )
        instance.validate()
        return instance


@dataclass(slots=True)
class AgentQueryPayload:
    request_id: str
    question: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id cannot be empty")
        if not self.question.strip():
            raise ValueError("question cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "request_id": self.request_id,
            "question": self.question,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class AgentReplyPayload:
    request_id: str
    response: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id cannot be empty")
        if not self.response.strip():
            raise ValueError("response cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "request_id": self.request_id,
            "response": self.response,
            "metadata": dict(self.metadata),
        }
