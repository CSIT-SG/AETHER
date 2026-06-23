import asyncio
import unittest

from ainalyse.chatbot.chatbot_agent import (
    ChatbotContextSummarizer,
    ChatbotAgentState,
    ChatbotAgent,
    TaskStatus,
)
from ainalyse.chatbot.specialist_registry import SpecialistAgentSpec
from ainalyse.chatbot.chatbot_ida import ChatbotToolbox, NullChatbotBackendBridge, ToolNames


class FakeBridge(NullChatbotBackendBridge):
    def __init__(self):
        self.functions = {"main": 0x1000, "helper": 0x1010}
        self.fastlook_requested = False
        self.custom_advice = None
        self.script_request = None

    def resolve_function(self, function_name: str):
        return self.functions.get(function_name)

    def get_function_name(self, function_ref):
        for name, ref in self.functions.items():
            if ref == function_ref:
                return name
        return hex(function_ref)

    def list_functions(self):
        return [{"name": name, "address": hex(ref)} for name, ref in self.functions.items()]

    def get_function_pseudocode(self, function_name: str):
        if function_name == "main":
            return "int main(void) { return 0; }"
        return None

    def get_data_at_address(self, location: str, count: int = 16):
        if location == "main":
            return {"ea": "0x1000", "bytes": "90", "string": "No string found"}
        return None

    def get_xrefs_to(self, location: str):
        if location == "main":
            return [{"from": "0x2000", "name": "caller", "type": "Code_Call"}]
        return []

    def annotate_function(self, advice: str = ""):
        if advice:
            self.custom_advice = advice
            return "Queued custom annotation for 'main' at 4096."
        self.fastlook_requested = True
        return "Queued fastlook annotation for 'main' at 4096."

    def generate_python_script(self, func_name: str, objective: str):
        self.script_request = (func_name, objective)
        return "Opened Script Generation Window"

    def create_struct(self, struct_name: str, size: int = 0, replace_if_exists: bool = False):
        return f"Struct '{struct_name}' created."


class ChatbotBackendTests(unittest.TestCase):
    def test_agent_registers_native_tool_definitions(self):
        agent = ChatbotAgent()
        definitions = agent.get_tool_definitions()
        names = {tool["function"]["name"] for tool in definitions}

        self.assertIn(ToolNames.ADD_ACTION_PLAN.value, names)
        self.assertIn(ToolNames.GET_FUNCTION_PSEUDOCODE.value, names)
        self.assertIn(ToolNames.ANNOTATE_FUNCTION.value, names)
        self.assertIn(ToolNames.GENERATE_PYTHON_SCRIPT.value, names)
        self.assertIn(ToolNames.SAVE_SUMMARY.value, names)
        self.assertIn(ToolNames.SEARCH_MEMORY.value, names)
        self.assertIn(ToolNames.DELEGATE_STRUCT_TASK.value, names)

    def test_execute_tool_calls_uses_named_arguments(self):
        agent = ChatbotAgent(bridge=FakeBridge())

        outputs = agent.execute_tool_calls(
            [
                {
                    "id": "call_1",
                    "name": ToolNames.ADD_ACTION_PLAN.value,
                    "arguments": {"plan_index": "0", "description": "Investigate"},
                },
                {
                    "id": "call_2",
                    "name": ToolNames.ADD_TASK_TO_PLAN.value,
                    "arguments": {"plan_index": "0", "task_index": "0", "description": "Read pseudocode"},
                },
            ]
        )

        self.assertEqual(outputs[0]["content"], "Action plan 0 added: Investigate")
        self.assertEqual(outputs[1]["content"], "Task 0 added to plan 0: Read pseudocode")

    def test_state_and_toolbox_support_legacy_plan_memory_and_ida_actions(self):
        state = ChatbotAgentState(bridge=FakeBridge())
        toolbox = ChatbotToolbox(state)

        self.assertEqual(toolbox.add_action_plan("0", "Investigate"), "Action plan 0 added: Investigate")
        self.assertEqual(toolbox.add_task_to_plan("0", "0", "Read pseudocode"), "Task 0 added to plan 0: Read pseudocode")
        self.assertEqual(toolbox.update_task("0", "0", TaskStatus.IN_PROGRESS.value), "Task 0 in plan 0 updated to In Progress")
        self.assertEqual(
            toolbox.add_memory("goal", "find entrypoint", "analysis_context", "HIGH", ["entrypoint"]),
            "Memory stored successfully (Key: goal, Category: analysis_context, Priority: HIGH)",
        )
        self.assertIn("find entrypoint", toolbox.search_memory("entrypoint", "3"))
        self.assertEqual(toolbox.add_to_function_list("main"), "Added 'main' to analysis list.")
        self.assertEqual(toolbox.get_function_pseudocode("main"), "int main(void) { return 0; }")
        self.assertIn("main", toolbox.list_functions())
        self.assertIn("Data at 0x1000", toolbox.get_data_at_address("main"))
        self.assertIn("caller", toolbox.get_xrefs_to("main"))
        self.assertIn("Queued fastlook", toolbox.annotate_function())
        self.assertIn("Queued custom", toolbox.annotate_function("focus on strings"))
        self.assertEqual(toolbox.generate_python_script("main", "extract strings"), "Opened Script Generation Window")
        self.assertIn("Read pseudocode", str(state))
        state_text = str(state)
        self.assertIn("Total Memories: 1", state_text)
        self.assertIn("Tags: [entrypoint]", state_text)
        self.assertNotIn("find entrypoint", state_text)
        self.assertNotIn("Last Action", state_text)
        self.assertNotIn("Last Result", state_text)

    def test_save_summary_compresses_history_and_preserves_recent_exchange(self):
        state = ChatbotAgentState(bridge=FakeBridge())
        state.conversation_history = [
            {"role": "user", "content": "first prompt"},
            {"role": "assistant", "content": "intermediate"},
            {"role": "user", "content": "latest question"},
            {"role": "assistant", "content": "latest answer"},
        ]
        toolbox = ChatbotToolbox(state)

        result = toolbox.save_summary("condensed summary")

        self.assertEqual(result, "Conversation history summarized.")
        self.assertIn("[CONVERSATION SUMMARY]", state.conversation_history[0]["content"])
        self.assertIn("Analyzed 2 conversation turns", state.conversation_history[0]["content"])
        self.assertEqual(state.conversation_history[-2]["content"], "latest question")
        self.assertEqual(state.conversation_history[-1]["content"], "latest answer")

    def test_context_summarizer_rewrites_history(self):
        state = ChatbotAgentState(bridge=FakeBridge())
        state.conversation_history = [
            {"role": "user", "content": "start"},
            {"role": "assistant", "content": "working"},
        ]
        toolbox = ChatbotToolbox(state)
        summarizer = ChatbotContextSummarizer(toolbox=toolbox)

        result = asyncio.run(summarizer.summarize(state))

        self.assertIn("start", result)
        self.assertIn("working", result)
        self.assertIn("[CONVERSATION SUMMARY]", state.conversation_history[0]["content"])

    def test_send_struct_message_returns_text(self):
        agent = ChatbotAgent(bridge=FakeBridge())
        struct_agent = agent.specialist_orchestrator.specialists.get("struct_agent")
        struct_agent.handle_text_request = lambda text, request_id="": f"struct-reply:{text}"  # type: ignore[method-assign]
        response = agent.specialist_orchestrator.send_struct_message(message="hello struct")
        self.assertEqual(response, "struct-reply:hello struct")

    def test_delegate_struct_task_tool(self):
        state = ChatbotAgentState(bridge=FakeBridge())
        agent = ChatbotAgent(bridge=FakeBridge())
        state.specialist_orchestrator = agent.specialist_orchestrator
        toolbox = ChatbotToolbox(state)

        output = toolbox.delegate_struct_task(
            "please inspect parser state struct",
            ["main"],
            "parser state context",
        )
        self.assertTrue(isinstance(output, str))

    def test_can_register_additional_specialist_agent(self):
        agent = ChatbotAgent(bridge=FakeBridge())

        class DummySpecialist:
            pass

        def handler(message, ctx):
            return None

        agent.specialist_orchestrator.register_specialist_agent(
            SpecialistAgentSpec(
                agent_id="dummy_specialist",
                capability="dummy_capability",
                description="Dummy specialist for extensibility test",
            ),
            lambda: DummySpecialist(),
            handler,
        )

        self.assertIn("dummy_specialist", agent.specialist_orchestrator.specialists)
        self.assertTrue(agent.specialist_orchestrator.specialist_registry.contains("dummy_specialist"))


if __name__ == "__main__":
    unittest.main()
