# CHANGELOG

## v1.0.0 - FIRST RELEASE

### Versioning Change

All future AETHER releases will follow the format of `vA.B.C`, starting with this release at v1.0.0

Where:
- A = Breaking Change
- B = New Feature
- C = Patches

### ARCHITECTURE OVERHAUL

![NEW ARCHITECTURE](../AETHER-next/apps/docs/public/architecture.svg)

#### Previously, AETHER used IDA-PRO-MCP in 2 main ways:
- In-built functions (Annotation, Struct Creation, etc): Programmatically invoked MCP tools within the code itself to perform tasks such as retrieving metadata or looking up functions by name. For these functions, tools are not exposed to LLM.
- Chatbot: MCP Tools are directly exposed to chatbot and its specialists, allowing them to call tools to interact with IDA in order perform their tasks.

#### However, with our new architecture:
- IDA-PRO-MCP is replaced with our own AETHER Backend and AETHER RPC. AETHER Backend manages connections between the many IDA Pro instances and implements agentic tool call logic, exposing a higher level API to the LLM. Also manages chatbot memory and holds system prompts. AETHER RPC provides a low level interface to IDA Pro’s API, exposing it as a JSON-RPC server.
- For all functions (Annotation, Struct Creation, Chatbot, etc), necessary tools are directly exposed to the LLM, giving the LLM more flexibility in performing its task.

### NEW FEATURES

- Added headless (CLI) support
- Unflattener
- Generate Report

### CURRENTLY IN DEVELOPMENT

- Function Indexing