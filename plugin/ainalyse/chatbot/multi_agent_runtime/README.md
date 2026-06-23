# multi-agent-runtime

Standalone Python project for building multiple agents in code and letting them communicate through a shared runtime.

## What it provides

- Register any number of agents
- Send direct messages between agents
- Broadcast messages to all agents
- Create agents from simple Python callbacks or classes
- Configure extra tools per agent at creation time
- Always inject mandatory `planning`, `context`, and `memory` tools
- Run the collaboration loop until the system becomes idle

## Quick start

```python
from multi_agent_runtime import CallbackAgent, FunctionTool, MultiAgentRuntime


def planner(agent, message, ctx):
    if message.topic == "start":
        ctx.tools["planning"].create_plan(
            ctx,
            goal="Coordinate a research workflow",
            actions=[
                {"description": "Ask researcher for risks"},
                {"description": "Hand results to reporter"},
            ],
        )
        ctx.send("researcher", "Find the key risks in this sample", topic="research")
    elif message.topic == "research_result":
        ctx.send("reporter", f"Write the report using: {message.content}", topic="draft")


def researcher(agent, message, ctx):
    if message.topic == "research":
        ctx.tools["memory"].remember(ctx, "credential theft")
        ctx.reply(message, "Risk 1: credential theft. Risk 2: persistence.")


def reporter(agent, message, ctx):
    if message.topic == "draft":
        rendered = ctx.tools["formatter"].invoke(ctx, message.content)
        ctx.publish("final_report", f"Final report: {rendered}")


def formatter(ctx, content):
    return f"[formatted] {content}"


runtime = MultiAgentRuntime()
runtime.add_agent(CallbackAgent("planner", planner))
runtime.add_agent(CallbackAgent("researcher", researcher))
runtime.add_agent(
    CallbackAgent(
        "reporter",
        reporter,
        tools=[FunctionTool("formatter", formatter)],
    )
)

runtime.send("system", "planner", "Begin", topic="start")
runtime.run()

print(runtime.shared_state["final_report"])
```

## Mandatory tools

Every agent automatically receives:

- `planning`
- `context`
- `memory`

These tools cannot be removed during agent creation. Extra tools can be added with the `tools=` argument.

## AgentBuilder

For less manual setup, use `AgentBuilder` to register handlers and tool factories once, then create agents from code or config.

```python
from multi_agent_runtime import AgentBuilder, FunctionTool, MultiAgentRuntime


runtime = MultiAgentRuntime()
builder = AgentBuilder(runtime)


def planner(agent, message, ctx):
    if message.topic == "start":
        ctx.send("reporter", "draft", topic="draft")


def reporter(agent, message, ctx):
    rendered = ctx.tools["uppercase"].invoke(ctx, message.content)
    ctx.publish("result", rendered)


def uppercase(ctx, value):
    return value.upper()


builder.register_handler("planner", planner)
builder.register_handler("reporter", reporter)
builder.register_function_tool("uppercase", uppercase)

builder.create_agents_from_config(
    {
        "agents": [
            {"agent_id": "planner", "handler": "planner"},
            {
                "agent_id": "reporter",
                "handler": "reporter",
                "tools": [{"kind": "function", "name": "uppercase"}],
            },
        ]
    }
)

runtime.send("system", "planner", "go", topic="start")
runtime.run()
print(runtime.shared_state["result"])
```

### Declarative config shape

```python
config = {
    "agents": [
        {
            "agent_id": "reporter",
            "handler": "reporter",
            "description": "Creates final output",
            "tools": [
                {"kind": "function", "name": "uppercase"},
                {"kind": "custom_tool_kind", "name": "formatter", "params": {"style": "short"}},
            ],
        }
    ]
}
```

`handler` is resolved through `builder.register_handler(...)`.
`kind` is resolved through either:

- `function`, using `builder.register_function_tool(...)`
- a custom tool factory registered with `builder.register_tool_factory(...)`

## Generic Backbone

The reusable agent backbone is now split out separately from any source-code or STIX domain logic.

Backbone components:

- `ContextBudget`
- `ContextManager`
- `BlockBuffer`
- `ConversationSummarizer`
- `ToolOutputBuffer`
- `AgentLoopExecutor`
- `HierarchicalRetrievalAgent`

Memory retrieval defaults to `KeywordRetrievalAgent`. To use LLM-guided tree traversal, create a `HierarchicalRetrievalAgent` with an LLM-like client that implements `evaluate_relevance_batch(...)` and `decide_branch_priority_batch(...)`, then install it with `memory_store.set_retrieval_agent(...)`.

The runtime includes an OpenAI-compatible implementation:

```python
from multi_agent_runtime import HierarchicalRetrievalAgent, MemoryStore, OpenAILLMClient

memory_store = MemoryStore()
llm_client = OpenAILLMClient(model="gpt-4o-mini")
memory_store.set_retrieval_agent(HierarchicalRetrievalAgent(memory_store, llm_client))
```

`OpenAILLMClient` also implements the memory organization hooks used by `MemoryStore.add_memory_auto(...)` and memory reorganization: `select_best_node(...)` and `analyze_and_categorize(...)`.

Higher-level domain-neutral agent layer:

- `GenericBackboneAgent`
- `BackboneCheckpoint`
- `BackboneCheckpointManager`
- `InMemoryBackboneStore`
- `SimplePlanManager`
- `PromptConfig`
- `PromptComposer`

These are available from `multi_agent_runtime`, `multi_agent_runtime.runtime.agent`, `multi_agent_runtime.runtime.context`, `multi_agent_runtime.services.memory`, and `multi_agent_runtime.services.planning`. They can be used to build non-ttphunter agents on top of the same planning, memory, tool buffering, summarization, and prompt-assembly foundation.

## Chatbot Integration

`chatbot` uses the generic runtime building blocks from `multi_agent_runtime`, but the chatbot-specific agent and IDA integration now live outside this package.

The reusable runtime remains domain-neutral. The chatbot-specific pieces live under the outer `chatbot` package, with the IDA-facing bridge and tool surface under `chatbot/chatbot_ida/`.

Example:

```python
from multi_agent_runtime import GenericBackboneAgent, PromptConfig


agent = GenericBackboneAgent(
    prompt_config=PromptConfig(
        identity="You are a research agent.",
        capability="Investigate the task using the configured tools.",
        output_format="Return a concise summary.",
    )
)
agent.register_tool(
    name="echo",
    description="Echo a value",
    parameters={
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
    },
    handler=lambda value: value,
)
```

`PromptConfig` is modular. Memory and planning instructions are always injected through shared prompt modules unless you explicitly bypass the composer with a raw `system_prompt=` override.

## Run the bundled demo

```bash
PYTHONPATH=projects python -m multi_agent_runtime
```

The copied chatbot UI code now lives in `viewer.py`. It is intentionally not imported from `multi_agent_runtime.__init__` because that viewer depends on IDA and PyQt at import time.
