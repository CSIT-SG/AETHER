import unittest

from multi_agent_runtime.runtime.agent.loop import AgentLoopExecutor


class DummyMessage:
    def __init__(self, *, content="", reasoning=None, tool_calls=None):
        self.content = content
        self.reasoning = reasoning
        self.tool_calls = tool_calls


class DumpingDummyMessage(DummyMessage):
    def model_dump(self):
        return {
            "role": "assistant",
            "content": self.content,
            "reasoning": self.reasoning,
            "reasoning_details": [{"text": self.reasoning}],
            "tool_calls": self.tool_calls,
        }


class DummyFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class DummyToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = DummyFunction(name, arguments)


class DummyChoice:
    def __init__(self, message):
        self.message = message


class DummyResponse:
    def __init__(self, message):
        self.choices = [DummyChoice(message)]


class DummyCompletions:
    def __init__(self, messages):
        self._messages = list(messages)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return DummyResponse(self._messages.pop(0))


class DummyChat:
    def __init__(self, messages):
        self.completions = DummyCompletions(messages)


class DummyClient:
    def __init__(self, messages):
        self.chat = DummyChat(messages)


class DummyContextManager:
    def __init__(self):
        self.tool_results = []

    def assemble_prompt(self, **kwargs):
        class Assembled:
            pass

        assembled = Assembled()
        assembled.messages = [{"role": "system", "content": kwargs["system_prompt"]}]
        if kwargs.get("current_task"):
            assembled.messages.append({"role": "user", "content": kwargs["current_task"]})
        assembled.conversation_history = kwargs["conversation_history"]
        return assembled

    def add_tool_result(self, name, args, result, tool_call_id=""):
        self.tool_results.append((name, args, result, tool_call_id))

    def get_statistics(self):
        return {}


class DummyPlanManager:
    active_plan = None

    def summary(self):
        return {}


class ExecutorReasoningTests(unittest.TestCase):
    def test_copy_reasoning_to_content_replaces_content_when_reasoning_exists(self):
        executor = AgentLoopExecutor(
            client=None,
            model="test-model",
            max_iterations=1,
            system_prompt="system",
            tools=[],
            tool_handlers={},
            context_manager=None,
            plan_manager=None,
            memory_store=None,
            copy_reasoning_to_content=True,
        )

        message = DummyMessage(content="final answer", reasoning="internal reasoning")
        built = executor._build_history_assistant_message(message)

        self.assertEqual(built["content"], "internal reasoning")

    def test_copy_reasoning_to_content_keeps_content_when_reasoning_missing(self):
        executor = AgentLoopExecutor(
            client=None,
            model="test-model",
            max_iterations=1,
            system_prompt="system",
            tools=[],
            tool_handlers={},
            context_manager=None,
            plan_manager=None,
            memory_store=None,
            copy_reasoning_to_content=True,
        )

        message = DummyMessage(content="final answer", reasoning=None)
        built = executor._build_history_assistant_message(message)

        self.assertEqual(built["content"], "final answer")

    def test_history_message_strips_reasoning_fields_from_model_dump(self):
        executor = AgentLoopExecutor(
            client=None,
            model="test-model",
            max_iterations=1,
            system_prompt="system",
            tools=[],
            tool_handlers={},
            context_manager=None,
            plan_manager=None,
            memory_store=None,
        )

        message = DumpingDummyMessage(content="final answer", reasoning="internal reasoning")
        built = executor._build_history_assistant_message(message)

        self.assertEqual(built, {"role": "assistant", "content": "final answer"})

    def test_step_returns_intermediate_tool_results_and_preserves_state(self):
        client = DummyClient(
            [
                DummyMessage(
                    tool_calls=[
                        DummyToolCall("call_1", "echo", '{"value": "hello"}'),
                    ]
                ),
                DummyMessage(content="done"),
            ]
        )
        context_manager = DummyContextManager()
        executor = AgentLoopExecutor(
            client=client,
            model="test-model",
            max_iterations=3,
            system_prompt="system",
            tools=[],
            tool_handlers={"echo": lambda value: f"echo:{value}"},
            context_manager=context_manager,
            plan_manager=DummyPlanManager(),
            memory_store=None,
        )

        state = executor.create_state("do work")
        first = executor.step(state)

        self.assertFalse(first.done)
        self.assertEqual(first.tool_results[0]["name"], "echo")
        self.assertEqual(first.tool_results[0]["result"], "echo:hello")
        self.assertEqual(state.iteration, 1)
        self.assertEqual(state.tool_calls_made, [{"name": "echo", "result": "echo:hello"}])
        self.assertEqual(state.conversation_history[-1]["role"], "tool")

        second = executor.step(state)

        self.assertTrue(second.done)
        self.assertEqual(second.final_analysis, "done")
        self.assertEqual(state.iteration, 2)

    def test_run_keeps_existing_result_shape_when_step_api_is_unused(self):
        client = DummyClient([DummyMessage(content="done")])
        executor = AgentLoopExecutor(
            client=client,
            model="test-model",
            max_iterations=3,
            system_prompt="system",
            tools=[],
            tool_handlers={},
            context_manager=DummyContextManager(),
            plan_manager=DummyPlanManager(),
            memory_store=None,
        )

        result = executor.run("do work")

        self.assertEqual(result["task"], "do work")
        self.assertEqual(result["iterations"], 1)
        self.assertEqual(result["tool_calls"], [])
        self.assertEqual(result["final_analysis"], "done")


if __name__ == "__main__":
    unittest.main()
