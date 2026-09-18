# CHANGELOG

## v1.0.0

### New Features

- Added headless (CLI) support
- Unflattener
- Generate Report

### Architecture Overhaul

![NEW ARCHITECTURE](/apps/docs/public/architecture.svg)

#### Previously, AETHER used IDA-PRO-MCP in 2 main ways:
- In-built Functions: Programmatically invoked MCP tools within the code itself to perform tasks such as retrieving metadata or looking up functions by name. For these functions, tools are not exposed to LLM.
- Chatbot: MCP Tools are directly exposed to chatbot and its specialists, allowing them to call tools to interact with IDA in order perform their tasks.

#### What's New:
- IDA-PRO-MCP is replaced with our own AETHER Backend and AETHER RPC. 
  - AETHER Backend manages connections between the many IDA Pro instances and implements agentic tool call logic, exposing a higher level API to the LLM. It also manages chatbot memory and holds system prompts. 
  - AETHER RPC provides a low level interface to IDA Pro’s API, exposing it as a RPYC server.
- All tools are directly exposed to the LLM, which allows it to select and invoke the tools needed for each task.

### Notes
#### Versioning Change
Future AETHER releases will use semantic versioning and follow the format of `vMAJOR.MINOR.PATCH`.

Find the documentations for setup and migration here:
- [Migration Guide](/apps/docs/src/content/migration.mdx)
- [GUI User Guide](/apps/docs/src/content/user-guide-gui.mdx)
- [CLI User Guide](/apps/docs/src/content/user-guide-cli.mdx)

#### In Development
 - Function Indexing