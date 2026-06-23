# chatbot Architecture

`chatbot` is the AETHER IDA chatbot implementation. It combines a PyQt/IDA UI, an OpenAI chat-completions loop with native function calling, and a small per-agent runtime used for state, plans, and memory.

## Package Layout

- `controller.py`: UI-facing orchestration. It queues user input, assembles prompts, calls the LLM, executes tool calls on the IDA main thread, and updates the chat view.
- `ui/`: PyQt widgets and context menu wiring for the chatbot view.
- `chatbot_agent.py`: LLM-facing agent wrapper, normalized completion payload handling, agent state, plan/memory formatting, and conversation summarization.
- `chatbot_ida/`: IDA-specific backend bridge and tool implementations exposed to the model.
- `backend/`: supporting dialogs, tool config persistence, and IndexAgent integration.
- `multi_agent_runtime/`: domain-neutral runtime primitives for agent context, memory stores, planning, message passing, and reusable backbone components.
- `prompts/`: base chatbot prompt, index prompt, and summarizer prompt.
- `tests/`: unit tests for chatbot backend behavior; `multi_agent_runtime/tests/` covers the standalone runtime.

## Runtime Flow

1. The UI creates a persistent `ChatbotController`.
2. The controller creates one persistent `ChatbotAgent`.
3. `ChatbotAgent` owns:
   - `ChatbotAgentState`
   - `ChatbotToolbox`
   - native OpenAI-compatible tool definitions
4. When the user sends a message, `ChatbotController.send_message()`:
   - prepends any manually selected binary-function context
   - appends a state snapshot to the user turn
   - queues the packet onto a worker-owned asyncio queue
5. `_process_message_thread()` builds the message list and calls the LLM in a worker thread.
6. `_handle_llm_response()` runs back on the IDA/Qt main thread. It:
   - renders assistant text
   - stores the assistant message in conversation history
   - validates and executes native tool calls
   - appends tool outputs to the next LLM turn
   - finalizes when there is no further tool work

Tool execution is intentionally done on the main thread because many IDA APIs are not safe from arbitrary worker threads.

## Prompt Assembly

Prompt assembly happens in `ChatbotController._process_message_thread()`.

The system prompt is:

1. `prompts/base_chat.txt`
2. `ChatbotController._build_tool_prompt()`

`base_chat.txt` is loaded through `_load_base_prompt()`. It is evaluated as an f-string with `ToolNames` and `TaskStatus` available, so the prompt can embed current tool names and status values without hardcoding strings in multiple places.

`_build_tool_prompt()` appends an `AGENT TOOL STATUS` block with:

- enabled tools that are actually available at runtime
- user-disabled tools from `backend/toolconfig.py`
- runtime-locked tools, such as index tools disabled after indexing was declined
- an instruction to use native tool calling instead of fenced text tool syntax

The user message added to conversation history is assembled as:

1. `--- AGENT STATE START ---`
2. `str(self.agent_state)`
3. `--- AGENT STATE END ---`
4. `USER QUERY:` or `[**USER INTERRUPT/OVERRIDE**]`
5. the actual user content

`str(self.agent_state)` renders:

- short-term memory entries
- all current action plans and task statuses
- active function list
- last action
- last result

Manual function context is inserted before the user text by `_settle_manual_context()`. This context is generated from functions selected through the context menu and tells the model to prioritize those functions.

The final message list sent to the LLM is:

```text
[
  {"role": "system", "content": base_prompt + tool_status_prompt},
  ...agent_state.conversation_history
]
```

Conversation history contains user turns, assistant turns, and native `tool` messages. Tool outputs are appended as OpenAI tool messages and fed back into the next completion request.

To prevent stale state buildup, `_keep_latest_agent_state()` removes older embedded agent-state snapshots and keeps only the latest user-turn snapshot.

## Completion And Tool Loop

`ChatbotAgent.create_completion()` calls `client.chat.completions.create()` with:

- configured model from `OPENAI_MODEL`
- `CHATBOT_MAX_TOKENS`
- `temperature=0.7`
- enabled native tool definitions from `ChatbotToolbox.get_tool_definitions()`
- `tool_choice="auto"`

Responses are normalized into:

- `content`: assistant text
- `tool_calls`: list of `{id, name, arguments}`

If the assistant returns tool calls, `_handle_llm_response()` filters them before execution:

- blocks tools disabled by user settings
- blocks unknown tools
- enforces `MAX_TOOL_CALLS = 10`
- enforces cumulative tool-output budget based on `CHATBOT_MAX_TOKENS`

Allowed tool calls are executed through `ChatbotAgent.execute_tool_calls()`, which delegates to `ChatbotToolbox.execute_named()`.

If tool outputs exist, they are enqueued as a `tool_output` packet and the loop continues. If the model returns text without tool calls, or removes the final action plan, the controller finalizes and clears transient conversation state.

## Available Chatbot Tools

Tools are defined in `chatbot_ida/toolset.py` as `ToolNames` and `CHATBOT_TOOL_SPECS`.

Task and plan tools:

- `add_action_plan`: create a new action plan.
- `add_task_to_plan`: add a task to an existing plan.
- `update_task`: set task status to `Not Started`, `In Progress`, `Completed`, or `Failed`.
- `remove_task_from_plan`: remove a task.
- `remove_action_plan`: remove a completed or abandoned plan.

Memory tools:

- `add_memory`: store a memory item with `key`, `value`, `category`, optional `priority`, and optional `tags`.
- `remove_memory`: remove memory by `memory_id`, key, or display index.

Binary-analysis tools:

- `list_functions`: list functions in the current IDB.
- `get_function_pseudocode`: retrieve Hex-Rays pseudocode for a function.
- `get_data_at_address`: inspect bytes, strings, disassembly, symbol hints, segment context, pointer candidates, and xrefs for a location.
- `get_xrefs_to`: list cross-references to a function or address.
- `add_to_function_list`: add a function to the active analysis list.
- `remove_from_function_list`: remove a function from the active analysis list.

Automation/action tools:

- `annotate_function`: perform an automated analysis of the current IDA function to add comments and renames, with optional guidance.
- `generate_python_script`: open the script generation workflow for a function and objective.
- `save_summary`: compress conversation history into a summary block.

Index tools:

- `search_indexed_functions`: keyword search over indexed function metadata.
- `get_function_index_summary`: summarize index size, state, importance distribution, and tags.
- `get_indexed_function_detail`: retrieve indexed metadata for one function.
- `ask_index_agent`: ask `IndexAgent` to answer a natural-language query using the function index.

Index tools are guarded by `_ensure_index_ready()`. If no usable index exists, the chatbot can prompt to start indexing. If indexing is declined, direct index lookup tools are temporarily disabled until indexing is started or available.

## Tool Configuration

Tool enablement is persisted by `backend/toolconfig.py`.

- On Windows, config is stored under `%LOCALAPPDATA%\AETHER-IDA\chatbot-tool-config.json`.
- On other platforms, config is stored as `ainalyse/chatbot/tool-config.json`.

The config is validated against the current tool registry at load time. If tools are added, removed, or renamed, the file is recreated while preserving known settings when possible.

The context-menu tool settings dialog uses `ToolSelectionDialog` to update this config. The currently enabled set is copied into `ChatbotController.exposed_tools`.

## Context Management

There are three distinct context layers:

1. Prompt context: the current system prompt, tool-status prompt, latest agent-state snapshot, and recent conversation/tool messages sent to the LLM.
2. Agent context: runtime key/value state stored in `MultiAgentRuntime` for the chatbot agent.
3. Manual binary context: selected functions that are injected into the next user prompt only.

`ChatbotAgentState` stores its working state in the runtime context for the `chatbot` agent:

- `function_list`
- `last_action`
- `last_result`
- `conversation_history`

`function_list` is capped by `MAX_FUNCTION_LIST_SIZE = 10` and stores resolved function references through the backend bridge.

`conversation_history` is preserved on normal finalization so follow-up user queries continue with the previous chat context. Memory and function-list state also persist for the lifetime of the `ChatbotAgent` unless explicitly cleared through `clear_memory()` or chat history clearing.

Manual context is separate from `function_list`. It is selected in the UI, rendered as function pills, prepended to the next user query, then cleared immediately after sending.

## Memory Mechanism

Short-term chatbot memory is backed by `multi_agent_runtime.memory_store.MemoryStore`.

`add_memory` calls `ChatbotAgentState.add_memory()`, which:

- updates an existing memory if the key already exists
- otherwise creates a new `MemoryItem`
- stores it under the supplied category, defaulting internally to `chatbot_short_term`
- stores the supplied priority, defaulting to `MemoryPriority.MEDIUM`
- stores supplied tags, defaulting internally to `short_term`

Each memory item contains:

- `id`
- optional `key`
- `value`
- `category`
- priority
- timestamps
- tags
- related IDs
- metadata

Memory retrieval uses `KeywordRetrievalAgent` by default. It scores memories by keyword matches in display content and tags. The generic store also supports `HierarchicalRetrievalAgent`, which uses an LLM-like client to score memories and prioritize memory-tree branches during retrieval. The runtime includes `OpenAILLMClient`, `StrictOpenAILLMClient`, and `RelaxedOpenAILLMClient` for OpenAI-compatible retrieval, node selection, and memory categorization. The generic store also supports filtered search and optional tree reorganization once a node exceeds a threshold.

The chatbot prompt does not automatically run memory retrieval for every user query. Instead, the current memory store is rendered into the agent-state snapshot via `str(ChatbotAgentState)`, and the model can add or remove memory through tools.

`save_summary` is separate from short-term memory. It compresses conversation history into a system message containing:

- current agent-state block
- `### CONVERSATION SUMMARY`
- summary text
- the last exchange

The summarizer may call only `add_memory` while compressing, allowing important facts to survive history compression.

## Planning Mechanism

Plans are backed by `multi_agent_runtime.planning.PlanManager`.

`ChatbotAgentState` exposes plan operations through the chatbot tools:

- create plan
- add task
- update task
- remove task
- remove plan

Plan status is represented internally by runtime `ActionStatus` values and mapped to chatbot-facing `TaskStatus` values:

- `Not Started` maps to `pending`
- `In Progress` maps to `in_progress`
- `Completed` maps to `completed`
- `Failed` maps to `failed`

Plans are included in every current agent-state snapshot. The base prompt instructs the model to use plans to guide work and remove completed plans before final conclusion.

## IDA Backend Bridge

`chatbot_ida/bridge.py` abstracts IDA operations behind `ChatbotBackendBridge`.

The default implementation, `IDAChatbotBackendBridge`, handles:

- function listing and resolution
- pseudocode retrieval
- address/data inspection
- xref lookup
- FastLook/custom annotation scheduling
- Python script generation window launching

Tests can use `NullChatbotBackendBridge` or fake bridges so tool/state behavior can be validated without IDA.

## Lifecycle And Clearing State

`ClearChatHistory.clear_chat_history()` clears:

- visible chat history
- persistent UI message log
- agent memory
- conversation history
- runtime plans/context through `ChatbotAgentState.clear_memory()`

Normal completion preserves outstanding plans and conversation history, marks the controller as no longer running, and advances the generation counter so the completed worker exits before any follow-up query is processed by a new worker.

Force stop cancels the async pipeline, increments a generation counter, and swaps in a fresh queue so stale workers cannot consume later user input.

## Runtime Notes

`multi_agent_runtime` is reusable and intentionally domain-neutral. It provides:

- per-agent context dictionaries
- per-agent memory stores
- per-agent plan managers
- mandatory `planning`, `context`, and `memory` runtime tools
- direct message passing and shared-state publication

`chatbot` currently uses this runtime mostly as the backing store for one persistent chatbot agent, while IDA-specific behavior remains in `chatbot_ida/`.
