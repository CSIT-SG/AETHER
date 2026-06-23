import unittest

from multi_agent_runtime import AgentBuilder, FunctionTool, MultiAgentRuntime


class AgentBuilderTests(unittest.TestCase):
    def test_builder_creates_agent_from_spec(self):
        runtime = MultiAgentRuntime()
        builder = AgentBuilder(runtime)
        observed: dict[str, str] = {}

        def uppercase(ctx, value: str) -> str:
            return value.upper()

        def worker(agent, message, ctx):
            observed["value"] = ctx.tools["uppercase"].invoke(ctx, message.content)

        builder.register_handler("worker", worker)
        builder.register_function_tool("uppercase", uppercase)
        builder.create_agent_from_spec(
            {
                "agent_id": "worker-1",
                "handler": "worker",
                "tools": [{"kind": "function", "name": "uppercase"}],
            }
        )

        runtime.send("system", "worker-1", "hello", topic="start")
        runtime.run()

        self.assertEqual(observed["value"], "HELLO")

    def test_builder_creates_multiple_agents_from_config(self):
        runtime = MultiAgentRuntime()
        builder = AgentBuilder(runtime)

        def append_suffix(name: str, suffix: str, description: str = "") -> FunctionTool:
            def handler(ctx, value: str) -> str:
                return f"{value}{suffix}"

            return FunctionTool(name, handler, description=description)

        def planner(agent, message, ctx):
            if message.topic == "start":
                ctx.send("reporter", "draft", topic="draft")

        def reporter(agent, message, ctx):
            rendered = ctx.tools["suffixer"].invoke(ctx, message.content)
            ctx.publish("result", rendered)

        builder.register_handler("planner", planner)
        builder.register_handler("reporter", reporter)
        builder.register_tool_factory("suffixer", append_suffix)

        builder.create_agents_from_config(
            {
                "agents": [
                    {"agent_id": "planner", "handler": "planner"},
                    {
                        "agent_id": "reporter",
                        "handler": "reporter",
                        "tools": [
                            {
                                "kind": "suffixer",
                                "name": "suffixer",
                                "params": {"suffix": "-final"},
                            }
                        ],
                    },
                ]
            }
        )

        runtime.send("system", "planner", "go", topic="start")
        runtime.run()

        self.assertEqual(runtime.shared_state["result"], "draft-final")

    def test_builder_rejects_unknown_handler(self):
        runtime = MultiAgentRuntime()
        builder = AgentBuilder(runtime)

        with self.assertRaises(KeyError):
            builder.create_agents_from_config(
                {"agents": [{"agent_id": "missing", "handler": "unknown"}]}
            )


if __name__ == "__main__":
    unittest.main()
