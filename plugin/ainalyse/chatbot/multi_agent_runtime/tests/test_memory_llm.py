import unittest

from multi_agent_runtime import OpenAILLMClient


class FakeChatCompletions:
    def __init__(self, response_text):
        self.response_text = response_text

    def create(self, **kwargs):
        message = type("Message", (), {"content": self.response_text})()
        choice = type("Choice", (), {"message": message})()
        return type("Response", (), {"choices": [choice]})()


class FakeClient:
    def __init__(self, response_text):
        self.chat = type("Chat", (), {"completions": FakeChatCompletions(response_text)})()


class MemoryLLMClientTests(unittest.TestCase):
    def test_batch_relevance_parses_json_scores_and_applies_threshold(self):
        client = OpenAILLMClient(
            client=FakeClient('[{"score": 0.9, "reason": "direct"}, {"score": 0.1, "reason": "weak"}]'),
            relevance_threshold=0.3,
        )

        results = client.evaluate_relevance_batch("aes", ["AES key", "HTTP beacon"])

        self.assertEqual(results, [(0.9, "direct"), (0.0, "weak")])

    def test_branch_priority_uses_keyword_fallback_when_response_is_empty(self):
        client = OpenAILLMClient(client=FakeClient(""))

        score, reason = client.decide_branch_priority(
            query="crypto decrypt",
            node_name="crypto",
            node_description="decryption routines",
            sample_memories=[],
        )

        self.assertGreater(score, 0.0)
        self.assertEqual(reason, "keyword fallback")

    def test_categorization_parses_memory_numbers(self):
        client = OpenAILLMClient(
            client=FakeClient(
                '{"categories": [{"name": "Configuration", "description": "config findings", "memory_numbers": [1, 2]}]}'
            )
        )

        categories = client.analyze_and_categorize(
            node_name="root",
            node_description="all",
            memories=["config path found", "json setting parsed", "unrelated"],
            min_items_per_category=2,
        )

        self.assertEqual(categories[0]["name"], "Configuration")
        self.assertEqual(categories[0]["items"], ["config path found", "json setting parsed"])


if __name__ == "__main__":
    unittest.main()
