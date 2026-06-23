import unittest

from ainalyse.chatbot.agent_messaging import (
    AgentMessageTopic,
    AgentQueryPayload,
    AgentReplyPayload,
    StructRequestPayload,
    StructResponsePayload,
    StructTaskStatus,
)
from ainalyse.chatbot.specialist_registry import SpecialistAgentRegistry, SpecialistAgentSpec


class AgentMessagingTests(unittest.TestCase):
    def test_struct_request_payload_round_trip(self):
        payload = StructRequestPayload(
            suggested_struct_name="session_ctx",
            relevant_functions=["init_session", "parse_token"],
            context_description="Session object inferred from parser state transitions.",
            request_id="req-1",
        )

        as_dict = payload.to_dict()
        parsed = StructRequestPayload.from_dict(as_dict)

        self.assertEqual(parsed.suggested_struct_name, "session_ctx")
        self.assertEqual(parsed.relevant_functions, ["init_session", "parse_token"])
        self.assertEqual(parsed.context_description, "Session object inferred from parser state transitions.")

    def test_struct_response_payload_round_trip(self):
        payload = StructResponsePayload(
            status=StructTaskStatus.MODIFIED,
            details="Added fields at offsets 0x8 and 0x10.",
            requests_for_main_agent=["Please provide xrefs for session_ctx usage."],
            request_id="req-1",
        )

        as_dict = payload.to_dict()
        parsed = StructResponsePayload.from_dict(as_dict)

        self.assertEqual(parsed.status, StructTaskStatus.MODIFIED)
        self.assertEqual(len(parsed.requests_for_main_agent), 1)

    def test_agent_query_and_reply_require_request_id(self):
        with self.assertRaises(ValueError):
            AgentQueryPayload(request_id="", question="Need more function clues").to_dict()

        with self.assertRaises(ValueError):
            AgentReplyPayload(request_id="", response="Here are the clues").to_dict()

    def test_struct_response_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            StructResponsePayload.from_dict({"status": "partial", "details": "n/a"})

    def test_topic_names_are_stable(self):
        self.assertEqual(AgentMessageTopic.STRUCT_REQUEST.value, "struct_request")
        self.assertEqual(AgentMessageTopic.STRUCT_RESPONSE.value, "struct_response")
        self.assertEqual(AgentMessageTopic.AGENT_QUERY.value, "agent_query")
        self.assertEqual(AgentMessageTopic.AGENT_REPLY.value, "agent_reply")


class SpecialistRegistryTests(unittest.TestCase):
    def test_registry_registers_and_creates_specialist_agent(self):
        registry = SpecialistAgentRegistry()

        class DummyAgent:
            pass

        registry.register(
            SpecialistAgentSpec(
                agent_id="struct_agent",
                capability="struct_operations",
                description="Handles struct creation and updates.",
            ),
            lambda: DummyAgent(),
        )

        self.assertTrue(registry.contains("struct_agent"))
        created = registry.create("struct_agent")
        self.assertIsInstance(created, DummyAgent)

    def test_registry_rejects_duplicate_agent_id(self):
        registry = SpecialistAgentRegistry()
        spec = SpecialistAgentSpec(agent_id="struct_agent", capability="struct_operations")
        registry.register(spec, lambda: object())

        with self.assertRaises(ValueError):
            registry.register(spec, lambda: object())


if __name__ == "__main__":
    unittest.main()
