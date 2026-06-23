from __future__ import annotations

import time
from uuid import uuid4
from typing import Any

from .agent_messaging import AgentMessageTopic
from .multi_agent_runtime import CallbackAgent
from .multi_agent_runtime.runtime.models import Message
from .logging_utils import get_chatbot_logger
from .specialist_registry import SpecialistAgentRegistry, SpecialistAgentSpec
from .specialists import build_default_specialist_bindings
from .struct_agent import STRUCT_AGENT_ID


class SpecialistOrchestrator:
    def __init__(self, state):
        self.state = state
        self.logger = get_chatbot_logger("chatbot.specialist_orchestrator")
        self.specialist_registry = SpecialistAgentRegistry()
        self.specialists: dict[str, Any] = {}
        self._runtime_handlers: dict[str, Any] = {}
        self._specialist_jobs: dict[str, dict[str, Any]] = {}
        self._configure_defaults()
        self.register_runtime_agents()

    @staticmethod
    def _request_topic_for(agent_id: str) -> str:
        return f"{agent_id}_request"

    @staticmethod
    def _continue_topic_for(agent_id: str) -> str:
        return f"{agent_id}_continue"

    @staticmethod
    def _response_topic_for(agent_id: str) -> str:
        return f"{agent_id}_response"

    def _record_specialist_update(
        self,
        *,
        agent_id: str,
        response_text: str,
        transcript: list[str] | None = None,
        request_id: str = "",
    ) -> None:
        updates = self.state.context.setdefault("specialist_updates", [])
        updates.append(
            {
                "agent_id": str(agent_id or ""),
                "response_text": str(response_text or ""),
                "transcript": list(transcript or []),
                "request_id": str(request_id or ""),
            }
        )
        self.state.context["active_specialist_agent"] = str(agent_id or "")
        notifier = self.state.context.get("specialist_progress_notifier")
        if callable(notifier):
            try:
                notifier()
            except Exception:
                self.logger.debug("Specialist progress notifier failed", exc_info=True)

    def _configure_defaults(self) -> None:
        handler_map = {
            STRUCT_AGENT_ID: self._handle_struct_specialist_message,
        }
        for spec, factory, handler in build_default_specialist_bindings(self.state.bridge, handler_map):
            self.register_specialist_agent(spec, factory, handler)

    def register_specialist_agent(self, spec: SpecialistAgentSpec, factory, runtime_message_handler) -> None:
        self.specialist_registry.register(spec, factory)
        self.specialists[spec.agent_id] = self.specialist_registry.create(spec.agent_id)
        self._runtime_handlers[spec.agent_id] = runtime_message_handler

    def register_runtime_agents(self) -> None:
        runtime = self.state.runtime
        for spec in self.specialist_registry.list_specs():
            if spec.agent_id in runtime.agents:
                continue
            runtime.add_agent(
                CallbackAgent(
                    spec.agent_id,
                    lambda agent, message, ctx, agent_id=spec.agent_id: self._dispatch_specialist_runtime_message(agent_id, message, ctx),
                    description=spec.description,
                )
            )

    def _dispatch_specialist_runtime_message(self, agent_id: str, message: Message, ctx) -> None:
        handler = self._runtime_handlers.get(agent_id)
        if handler is not None:
            handler(message, ctx)

    def _start_specialist_job(
        self,
        *,
        agent_id: str,
        request_message: Message,
        request_id: str,
        session: dict[str, Any],
        ctx,
    ) -> None:
        self._specialist_jobs[request_id] = {
            "request_message": request_message,
            "agent_id": agent_id,
            "transcript_cursor": 0,
            "session": session,
        }
        ctx.send(
            agent_id,
            {"request_id": request_id},
            topic=self._continue_topic_for(agent_id),
            correlation_id=request_id,
        )

    def _step_specialist_job(self, *, agent_id: str, message: Message, ctx) -> bool:
        req_id = str((message.content or {}).get("request_id", ""))
        job = self._specialist_jobs.get(req_id)
        if not job or str(job.get("agent_id", "")) != agent_id:
            return True
        specialist = self.specialists.get(agent_id)
        session = job.get("session")
        request_message = job.get("request_message")
        if specialist is None or not isinstance(session, dict) or request_message is None:
            return True

        specialist.step_text_session(session)

        cursor = int(job.get("transcript_cursor", 0) or 0)
        snapshot = specialist.get_transcript_snapshot()
        if cursor < len(snapshot):
            for line in snapshot[cursor:]:
                if str(line or "").strip():
                    self._record_specialist_update(
                        agent_id=agent_id,
                        response_text="",
                        transcript=[str(line)],
                        request_id=req_id,
                    )
            job["transcript_cursor"] = len(snapshot)

        if not bool(session.get("done", False)):
            return False

        try:
            response_text = str(session.get("response_text", "") or f"{agent_id} returned an empty response.")
            transcript = specialist.consume_last_transcript()
            self.state.context[f"last_{agent_id}_transcript"] = transcript
            self._record_specialist_update(
                agent_id=agent_id,
                response_text=response_text,
                transcript=[],
                request_id=req_id,
            )
        except Exception as exc:
            self.logger.exception("%s handler failed: %s", agent_id, exc)
            response_text = f"{agent_id} failed: {exc}"
            transcript = [f"error: {exc}"]
            self.state.context[f"last_{agent_id}_transcript"] = transcript
            self._record_specialist_update(
                agent_id=agent_id,
                response_text=response_text,
                transcript=transcript,
                request_id=req_id,
            )
        finally:
            self._specialist_jobs.pop(req_id, None)

        ctx.reply(
            request_message,
            {
                "text": response_text,
                "request_id": req_id,
            },
            topic=self._response_topic_for(agent_id),
        )
        return True

    def _handle_struct_specialist_message(self, message: Message, ctx) -> None:
        struct_agent = self.specialists.get(STRUCT_AGENT_ID)
        if struct_agent is None:
            return
        struct_request_topic = self._request_topic_for(STRUCT_AGENT_ID)
        struct_continue_topic = self._continue_topic_for(STRUCT_AGENT_ID)
        if message.topic in (AgentMessageTopic.STRUCT_REQUEST.value, struct_request_topic):
            self.logger.info("Received struct request message_id=%s correlation_id=%s", message.id, message.correlation_id)
            payload = dict(message.content or {})
            req_id = str(payload.get("request_id", ""))
            session = struct_agent.create_text_session(
                str(payload.get("text", "")),
                req_id,
                list(payload.get("relevant_functions") or []),
                str(payload.get("context_description", "")),
            )
            self._start_specialist_job(
                agent_id=STRUCT_AGENT_ID,
                request_message=message,
                request_id=req_id,
                session=session,
                ctx=ctx,
            )
            return

        if message.topic in (AgentMessageTopic.STRUCT_CONTINUE.value, struct_continue_topic):
            self._step_specialist_job(agent_id=STRUCT_AGENT_ID, message=message, ctx=ctx)
            return

    def send_struct_message(
        self,
        *,
        message: str,
        relevant_functions: list[str],
        context_description: str = "",
        request_id: str | None = None,
    ) -> str:
        req_id = self.start_struct_message(
            message=message,
            relevant_functions=relevant_functions,
            context_description=context_description,
            request_id=request_id,
        )
        return self.wait_for_struct_response(req_id)

    def start_struct_message(
        self,
        *,
        message: str,
        relevant_functions: list[str],
        context_description: str = "",
        request_id: str | None = None,
    ) -> str:
        req_id = request_id or str(uuid4())
        self.logger.info("Sending struct message request_id=%s relevant_functions=%s", req_id, relevant_functions)
        runtime = self.state.runtime
        # Mark specialist as active while this request is being stepped.
        self.state.context["active_specialist_agent"] = STRUCT_AGENT_ID
        runtime.send(
            self.state.agent_id,
            STRUCT_AGENT_ID,
            {
                "text": str(message or ""),
                "relevant_functions": list(relevant_functions or []),
                "context_description": context_description,
                "request_id": req_id,
            },
            topic=self._request_topic_for(STRUCT_AGENT_ID),
            correlation_id=req_id,
        )
        return req_id

    def wait_for_struct_response(self, request_id: str, timeout_seconds: float = -1.0) -> str:
        req_id = str(request_id or "")
        runtime = self.state.runtime
        try:
            if timeout_seconds < 0:
                deadline = None
            else:
                deadline = time.time() + timeout_seconds
            while deadline is None or time.time() < deadline:
                if not runtime.step():
                    if req_id in self._specialist_jobs:
                        runtime.send(
                            self.state.agent_id,
                            STRUCT_AGENT_ID,
                            {"request_id": req_id},
                            topic=self._continue_topic_for(STRUCT_AGENT_ID),
                            correlation_id=req_id,
                        )
                        time.sleep(0.02)
                        continue
                    self.logger.info("Runtime step returned idle while waiting request_id=%s", req_id)
                    break
                for msg in reversed(runtime.history):
                    if msg.topic != self._response_topic_for(STRUCT_AGENT_ID):
                        continue
                    if msg.sender != STRUCT_AGENT_ID or msg.recipient != self.state.agent_id:
                        continue
                    if msg.correlation_id != req_id and str((msg.content or {}).get("request_id", "")) != req_id:
                        continue
                    response_text = str((msg.content or {}).get("text", "")).strip() or "Struct agent returned an empty response."
                    self.logger.info("Received struct response request_id=%s response_len=%s", req_id, len(response_text))
                    return response_text

            self.logger.warning("No struct response received request_id=%s timeout=%ss", req_id, timeout_seconds)
            return "No response received from StructAgent."
        finally:
            self.state.context["active_specialist_agent"] = ""
