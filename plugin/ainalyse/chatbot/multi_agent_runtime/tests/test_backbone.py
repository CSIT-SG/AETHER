import unittest

from multi_agent_runtime import InMemoryBackboneStore
from multi_agent_runtime.runtime.context import BlockBuffer, ContextBudget, ContextManager, ToolOutputBuffer


class StubExplorer:
    def __init__(self, files):
        self._files = files

    def list_files(self):
        return sorted(self._files.keys())


class BackboneTests(unittest.TestCase):
    def test_tool_buffer_records_and_truncates(self):
        buffer = ToolOutputBuffer(max_records=3, max_tokens=50)
        buffer.add("list_files", {}, "a" * 120)
        buffer.add("get_file_content", {"file_path": "a.py"}, "b" * 120)

        removed = buffer.truncate_to_tokens(20)

        self.assertGreaterEqual(removed, 0)
        self.assertLessEqual(buffer.current_tokens, 20)

    def test_block_buffer_summarizes_old_blocks(self):
        buffer = BlockBuffer(max_raw_blocks=1, max_tokens=100)
        buffer.add_message({"role": "assistant", "content": "step 1"})
        buffer.add_message({"role": "assistant", "content": "step 2"})

        self.assertTrue(buffer.needs_summarization())
        summarized = buffer.summarize_oldest_blocks()

        self.assertGreaterEqual(summarized, 1)
        self.assertTrue(buffer.variable_summary)

    def test_block_buffer_preserves_followup_user_after_assistant(self):
        buffer = BlockBuffer(max_raw_blocks=10, max_tokens=100)
        buffer.add_message({"role": "user", "content": "first question"})
        buffer.add_message({"role": "assistant", "content": "first answer"})
        buffer.add_message({"role": "user", "content": "follow up"})

        history = buffer.get_summarized_conversation_history()

        self.assertEqual(
            [message["content"] for message in history],
            ["first question", "first answer", "follow up"],
        )

    def test_block_buffer_summarizes_followup_content(self):
        buffer = BlockBuffer(max_raw_blocks=10, max_tokens=100)
        buffer.add_message({"role": "user", "content": "first question about registry persistence"})
        buffer.add_message({"role": "assistant", "content": "first answer explaining registry persistence"})
        buffer.add_message({"role": "user", "content": "follow up asking whether the function saves vsync"})
        buffer.add_message({"role": "assistant", "content": "follow up answer says it writes WaitForVSync"})

        summarized = buffer.summarize_oldest_blocks(num_blocks=1)

        self.assertEqual(summarized, 1)
        self.assertIn("The discussion focused on first question about registry persistence", buffer.variable_summary)
        self.assertNotIn("User asked:", buffer.variable_summary)
        self.assertNotIn("Assistant answered:", buffer.variable_summary)

    def test_context_manager_assembles_prompt_with_memories_and_files(self):
        memory_store = InMemoryBackboneStore()
        memory_store.add_memory(key="alpha", value="found credential logic", category="behavior")
        explorer = StubExplorer({"src/app.py": {"raw_content": "password = 1"}})
        manager = ContextManager(budget=ContextBudget(), memory_store=memory_store, explorer=explorer)
        manager.mark_file_analyzed("src/app.py")
        assembled = manager.assemble_prompt(
            system_prompt="System prompt",
            conversation_history=[{"role": "assistant", "content": "Earlier step"}],
            current_task="credential",
        )

        self.assertTrue(assembled.messages)
        self.assertIn("[FILES]", assembled.messages[0]["content"])
        self.assertIn("[RELEVANT FINDINGS]", assembled.messages[0]["content"])


if __name__ == "__main__":
    unittest.main()
