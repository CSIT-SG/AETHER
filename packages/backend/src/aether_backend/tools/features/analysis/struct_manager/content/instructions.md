Assist a human reverse engineer to manage structs via create and update operations. Doing so manually is tedious and mentally taxxing, you are here to help relief that.

The struct manager is na agent that can perform the following operations on a struct in IDA Pro:
- create struct
- rename structs
- add struct fields
- change struct field types
- change struct field size
- delete struct fields
- rename struct fields
- get struct info
- get struct IDs

# When to use this tool

use it whenever the user asks you to do anything struct related. If the user asks to determine a variable type, this tool can be used to determine that too.

# Parameters

## `operation` (required)
Either one of the three string literals `create`, `update` or `delete`. This determines the operation performed on the struct.

## `function_address` (required)
The effective address (EA) of the function to annotate. Must be a valid function entry point.

Acceptable forms:
- Hex string: `"0x140009050"`, `"0x14000905C"`.

If the address is invalid, is not the start of a function, or refers to a function that failed to decompile, the tool returns an error. Do not retry with the same address hoping it works — verify the address first using `get_function_by_address`.

Common mistakes to avoid:
- Passing an EA in the middle of a function. Use the function's *entry* EA.
- Passing an address from a data segment. Only code addresses inside functions work.
- Passing a stripped-down address like `"140009050"` without the `0x` prefix. Include the prefix or pass as int.

## `var_name` (required)
This is the name of the variable that the struct is applicable to.


## `custom_prompt` (optional)
Additional guidance for the annotator, tailored to what the user actually wants.

**Keep it focused.** The annotator already has strong default behavior (rename everything, comment where useful, verify the result). Do not restate the defaults; only add information the annotator wouldn't otherwise know.

Good use cases for `custom_prompt`:
- Domain hints: `"This binary is a game engine; the function may be related to physics or rendering."`
- Known context: `"The struct and its elements are called in the context of a network connection."`
- Naming conventions: `"Prefer Windows API convention (CamelCase). This is a Win32 binary."`

Bad use cases:
- Restating defaults: `"Please rename all variables and add comments."` — the annotator already does this.
- Over-specification: `"Rename v0 to buffer_size, v1 to counter, sub_X to init_crypto..."` — you're doing the annotator's job; let it decide.
- Long backstory: multi-paragraph descriptions of the binary's history dilute the actual guidance.

If you don't have specific guidance, omit the prompt entirely. An empty prompt is fine and often optimal.

Length guidance: 1-3 sentences. If your `custom_prompt` exceeds 3 sentences, you're probably over-specifying.

# Behaviour

The struct manager will:
1. Get the xrefs to the speicified variable in IDA. This is will be useful for understanding the struct
2. Determine the type of operation: `create`, `update` or `delete`.
3. call the respective agent for `create` and `update`. `delete` is performed without the use of an agent

If `create` 
1. Resolve the address of the function.
2. Gather contextual information like function pseudocode and metadata. This aids in understanding the context in which the varible exists.
3. create a struct in local types based on this derived information.

If `update`
1. Resolve the address of the function.
2. Gather contextual information like function pseudocode and metadata. This allows the agent to take into account newer annotations in the pseudocode.
3. Make appropriate changes to the struct.

If `delete`
1. determine the struct applied to a specified variable
2. delete the struct from local types

# What NOT to Do

- **Do not call this tool in a loop over many functions.** It is not designed for bulk operation. If the user wants many functions annotated, ask them to specify which ones or annotate the entry point and let the agent recursively annotate callees as needed.

- **Do not pass unrelated context in `custom_prompt`.** Information about other functions, unrelated user goals, or long conversational history all reduce annotation quality.
