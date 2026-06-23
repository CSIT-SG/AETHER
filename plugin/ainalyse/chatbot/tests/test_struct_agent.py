import unittest

from ainalyse.chatbot.agent_messaging import StructTaskStatus
from ainalyse.chatbot.chatbot_ida.bridge import NullChatbotBackendBridge
from ainalyse.chatbot.struct_agent import StructAgent


class FakeBridge(NullChatbotBackendBridge):
    def __init__(self):
        self.created = []

    def create_struct(self, struct_name: str, size: int = 0, replace_if_exists: bool = False) -> str:
        self.created.append((struct_name, size, replace_if_exists))
        return f"Struct '{struct_name}' created."


class StructAgentTests(unittest.TestCase):
    def test_handle_struct_request_created(self):
        agent = StructAgent(bridge=FakeBridge())
        response = agent.handle_struct_request(
            {
                "suggested_struct_name": "session_ctx",
                "relevant_functions": ["main", "parse"],
                "context_description": "Session state inferred from parser",
                "request_id": "req-1",
            }
        )
        self.assertEqual(response.status, StructTaskStatus.CREATED)
        self.assertIn("created", response.details.lower())

    def test_handle_struct_request_dry_run(self):
        bridge = FakeBridge()
        agent = StructAgent(bridge=bridge)
        response = agent.handle_struct_request(
            {
                "suggested_struct_name": "session_ctx",
                "relevant_functions": ["main"],
                "context_description": "state",
                "request_id": "req-2",
                "metadata": {"dry_run": True},
            }
        )
        self.assertEqual(response.status, StructTaskStatus.MODIFIED)
        self.assertEqual(bridge.created, [])

    def test_handle_struct_request_mutation_limit(self):
        agent = StructAgent(bridge=FakeBridge())
        response = agent.handle_struct_request(
            {
                "suggested_struct_name": "session_ctx",
                "relevant_functions": ["main"],
                "context_description": "state",
                "request_id": "req-3",
                "metadata": {"proposed_edits": [{}] * 30},
            }
        )
        self.assertEqual(response.status, StructTaskStatus.FAILED)
        self.assertEqual(response.metadata.get("error_code"), "MUTATION_LIMIT_EXCEEDED")

    def test_allowed_tool_enforcement(self):
        agent = StructAgent(bridge=FakeBridge())
        blocked = agent.execute_tool("annotate_function", {})
        self.assertIn("BLOCKED", blocked)


if __name__ == "__main__":
    unittest.main()
