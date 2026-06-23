import os
import tempfile
import unittest

from multi_agent_runtime import (
    GenericBackboneAgent,
    MemoryStore,
    PromptConfig,
    SHARED_MEMORY_PROMPT,
    SHARED_PLANNING_PROMPT,
)


class BackboneAgentTests(unittest.TestCase):
    def test_core_tools_are_registered(self):
        agent = GenericBackboneAgent()
        names = {tool["function"]["name"] for tool in agent.tools}
        self.assertEqual(
            names,
            {
                "create_plan",
                "update_plan",
                "delete_plan",
                "add_memory",
                "add_memory_auto",
                "search_memories",
                "get_context_statistics",
                "get_memory_statistics",
            },
        )

    def test_custom_tool_registration(self):
        agent = GenericBackboneAgent()
        agent.register_tool(
            name="echo",
            description="Echo text",
            parameters={"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]},
            handler=lambda value: value,
        )
        self.assertIn("echo", agent.tool_handlers)

    def test_checkpoint_roundtrip_preserves_state(self):
        agent = GenericBackboneAgent()
        agent.create_plan("Investigate", [{"description": "First"}])
        agent.add_memory("alpha", "value", "finding")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "checkpoint.json")
            agent.checkpoint_manager.save_checkpoint(agent.create_checkpoint("Continue"), path)
            restored = GenericBackboneAgent()
            checkpoint = restored.load_checkpoint(path)
        self.assertEqual(checkpoint.next_task, "Continue")
        self.assertEqual(restored.memory_store.get_statistics()["total_memories"], 1)
        self.assertEqual(restored.plan_manager.active_plan.goal, "Investigate")

    def test_run_without_client_returns_stub_result(self):
        agent = GenericBackboneAgent()
        result = agent.run("Do work")
        self.assertEqual(result["iterations"], 0)
        self.assertEqual(result["final_analysis"], "No LLM client configured.")

    def test_prompt_config_composes_custom_and_shared_sections(self):
        agent = GenericBackboneAgent(
            prompt_config=PromptConfig(
                identity="You are a reviewer.",
                capability="Review the supplied material.",
                output_format="Respond with short bullet points.",
            )
        )

        self.assertIn("You are a reviewer.", agent.system_prompt)
        self.assertIn("Review the supplied material.", agent.system_prompt)
        self.assertIn("Respond with short bullet points.", agent.system_prompt)
        self.assertIn(SHARED_MEMORY_PROMPT, agent.system_prompt)
        self.assertIn(SHARED_PLANNING_PROMPT, agent.system_prompt)

    def test_raw_system_prompt_override_bypasses_composer(self):
        agent = GenericBackboneAgent(system_prompt="raw override")
        self.assertEqual(agent.system_prompt, "raw override")

    def test_update_plan_supports_subactions_remove_and_progress(self):
        agent = GenericBackboneAgent()
        agent.create_plan(
            "Investigate parser",
            [{"description": "Inspect parser"}, {"description": "Review serializer"}],
        )
        parent_id = agent.plan_manager.active_plan.actions[0].id
        remove_id = agent.plan_manager.active_plan.actions[1].id

        update_result = agent.update_plan(
            add_actions=[{"description": "Trace parser helpers", "parent_action_id": parent_id}],
            start_action_ids=[parent_id],
            remove_action_ids=[remove_id],
        )

        self.assertIn("Added: [", update_result)
        self.assertIn(f"Removed: [{remove_id}]", update_result)
        parent = agent.plan_manager.active_plan.get_action(parent_id)
        self.assertEqual(len(parent.sub_actions), 1)
        self.assertEqual(parent.sub_actions[0].description, "Trace parser helpers")
        remaining = [action.description for action in agent.plan_manager.active_plan.iter_actions()]
        self.assertNotIn("Review serializer", remaining)

    def test_memory_store_auto_reorganizes_when_threshold_reached(self):
        store = MemoryStore(reorganization_threshold=2)
        store.add_memory(key="cred_one", value="credential read", category="credential")
        store.add_memory(key="cred_two", value="credential parse", category="credential")
        store.add_memory(key="net_one", value="network beacon", category="network")

        child_names = {child.name for child in store.root.children}
        self.assertIn("credential", child_names)
        self.assertEqual(len(store.root.children), 1)
        credential_node = next(child for child in store.root.children if child.name == "credential")
        credential_memories = store.get_memories_by_node(credential_node.id, include_children=False)
        self.assertEqual(len(credential_memories), 2)


if __name__ == "__main__":
    unittest.main()
