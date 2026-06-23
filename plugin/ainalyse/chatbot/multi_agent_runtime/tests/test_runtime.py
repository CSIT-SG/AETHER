import unittest

from multi_agent_runtime import CallbackAgent, FunctionTool, HierarchicalRetrievalAgent, MemoryStore, MultiAgentRuntime


class MultiAgentRuntimeTests(unittest.TestCase):
    def test_agents_can_exchange_messages_and_publish_state(self):
        runtime = MultiAgentRuntime()

        def alpha(agent, message, ctx):
            if message.topic == "start":
                ctx.send("beta", "ping", topic="ping")
            elif message.topic == "pong":
                ctx.publish("result", "completed")

        def beta(agent, message, ctx):
            if message.topic == "ping":
                ctx.reply(message, "pong", topic="pong")

        runtime.add_agent(CallbackAgent("alpha", alpha))
        runtime.add_agent(CallbackAgent("beta", beta))
        runtime.send("system", "alpha", "go", topic="start")

        steps = runtime.run()

        self.assertEqual(steps, 3)
        self.assertEqual(runtime.shared_state["result"], "completed")
        self.assertEqual([message.topic for message in runtime.history], ["start", "ping", "pong"])

    def test_broadcast_sends_to_all_other_agents(self):
        runtime = MultiAgentRuntime()
        received: list[tuple[str, str]] = []

        def sender(agent, message, ctx):
            if message.topic == "start":
                ctx.broadcast("hello", topic="notice")

        def collector(agent, message, ctx):
            received.append((agent.agent_id, message.content))

        runtime.create_agent("sender", sender)
        runtime.create_agent("one", collector)
        runtime.create_agent("two", collector)
        runtime.send("system", "sender", "go", topic="start")

        runtime.run()

        self.assertEqual(sorted(received), [("one", "hello"), ("two", "hello")])

    def test_mandatory_tools_are_always_available(self):
        runtime = MultiAgentRuntime()
        seen: dict[str, list[str]] = {}

        def inspector(agent, message, ctx):
            seen["tools"] = ctx.tools.names()
            ctx.tools["planning"].create_plan(ctx, "Inspect tools", [{"description": "verify mandatory tools"}])
            ctx.tools["memory"].remember(ctx, "mandatory-memory-present")
            ctx.tools["context"].set(ctx, "phase", "inspection")

        runtime.create_agent("inspector", inspector)
        runtime.send("system", "inspector", "inspect", topic="start")
        runtime.run()

        self.assertEqual(seen["tools"], ["context", "memory", "planning"])
        self.assertEqual(runtime._agent_context["inspector"]["phase"], "inspection")
        stored = list(runtime._agent_memory_stores["inspector"].memories.values())
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].key, "mandatory-memory-present")
        self.assertEqual(stored[0].value, "mandatory-memory-present")
        self.assertEqual(stored[0].category, "runtime")

    def test_agent_creation_can_attach_optional_tools(self):
        runtime = MultiAgentRuntime()
        published: dict[str, str] = {}

        def uppercase(ctx, value: str) -> str:
            return value.upper()

        def worker(agent, message, ctx):
            rendered = ctx.tools["uppercase"].invoke(ctx, message.content)
            published["value"] = rendered

        runtime.create_agent(
            "worker",
            worker,
            tools=[FunctionTool("uppercase", uppercase, description="Uppercases values")],
        )
        runtime.send("system", "worker", "hello", topic="start")
        runtime.run()

        self.assertEqual(published["value"], "HELLO")
        self.assertEqual(
            runtime.get_agent_tools("worker").keys(),
            {"context", "memory", "planning", "uppercase"},
        )

    def test_runtime_planning_supports_add_remove_and_marking(self):
        runtime = MultiAgentRuntime()
        observed: dict[str, object] = {}

        def worker(agent, message, ctx):
            planning = ctx.tools["planning"]
            planning.create_plan(
                ctx,
                "Coordinate",
                [{"description": "Inspect parser"}, {"description": "Review serializer"}],
            )
            first_step = ctx.plan_manager.active_plan.steps[0]
            second_step = ctx.plan_manager.active_plan.steps[1]
            planning.update_plan(ctx, add_actions=[{"description": "Trace parser helpers", "parent_action_id": first_step.id}])
            planning.update_plan(ctx, start_action_ids=[first_step.id])
            planning.update_plan(ctx, remove_action_ids=[second_step.id])
            observed["snapshot"] = ctx.plan_manager.active_plan

        runtime.create_agent("worker", worker)
        runtime.send("system", "worker", "go", topic="start")
        runtime.run()

        snapshot = observed["snapshot"]
        self.assertEqual(snapshot.goal, "Coordinate")
        self.assertEqual(snapshot.steps[0].status.value, "in_progress")
        self.assertEqual(snapshot.steps[0].steps[0].description, "Trace parser helpers")
        descriptions = [step.description for step in snapshot.steps]
        self.assertNotIn("Review serializer", descriptions)

    def test_runtime_agents_use_shared_backbone_memory_store(self):
        runtime = MultiAgentRuntime()
        observed: dict[str, object] = {}

        def inspector(agent, message, ctx):
            stored = ctx.tools["memory"].remember(
                ctx,
                {
                    "type": "analysis_result",
                    "task": "inspect parser flow",
                    "result": {"final_analysis": "done"},
                },
            )
            observed["stored"] = stored
            observed["matches"] = ctx.tools["memory"].search_memories(ctx, "analysis_result")

        runtime.create_agent("inspector", inspector)
        runtime.send("system", "inspector", "inspect", topic="start")
        runtime.run()

        stored = observed["stored"]
        matches = observed["matches"]
        self.assertEqual(stored.key, "analysis_result")
        self.assertEqual(stored.category, "analysis_result")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].memory.metadata["task"], "inspect parser flow")

    def test_hierarchical_retrieval_agent_uses_llm_guided_tree_search(self):
        class FakeLLM:
            def decide_branch_priority_batch(self, query, branches):
                return [
                    (0.95 if branch["name"] == "crypto" else 0.05, branch["name"])
                    for branch in branches
                ]

            def evaluate_relevance_batch(self, query, contents):
                return [
                    (0.9 if "aes" in content.lower() else 0.0, content)
                    for content in contents
                ]

        store = MemoryStore(auto_reorganize=False)
        crypto = store.create_node("crypto", "cryptography and decryption routines")
        network = store.create_node("network", "network indicators")
        aes_memory = store.add_memory(key="aes", value="AES key schedule found", category="finding", node_id=crypto.id)
        store.add_memory(key="http", value="HTTP beacon interval found", category="finding", node_id=network.id)
        store.set_retrieval_agent(HierarchicalRetrievalAgent(store, FakeLLM()))

        results = store.search_memories("aes decrypt", top_k=5)

        self.assertEqual([result.memory.id for result in results], [aes_memory.id])
        self.assertEqual(results[0].source_node_id, crypto.id)
        self.assertGreater(results[0].relevance_score, 0.8)

    def test_memory_search_falls_back_to_keyword_when_retriever_fails(self):
        class BrokenRetrievalAgent:
            def retrieve(self, query, top_k=10):
                raise RuntimeError("retriever unavailable")

        store = MemoryStore(auto_reorganize=False)
        store.add_memory(key="entrypoint", value="main dispatches commands", category="finding")
        store.set_retrieval_agent(BrokenRetrievalAgent())

        results = store.search_memories("dispatches", top_k=5)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].memory.key, "entrypoint")


if __name__ == "__main__":
    unittest.main()
