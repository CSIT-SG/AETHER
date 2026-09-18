Annotate a function in IDA Pro to make it more readable for a human reverse engineer.

The annotator is an autonomous agent that renames variables, arguments, and functions, and sets inline comments in the decompiler view. It analyzes the target function together with its callees to produce meaningful names and evidence-backed annotations.

# When to Use This Tool

Use it when the user asks you to:
- Analyze, understand, annotate, document, or explain a function in the binary.
- Make a function "more readable" or "easier to follow."
- Rename generic identifiers (`v0`, `sub_140009050`, `arg_10`) into meaningful ones.
- Comment on specific behavior in a function.

Do NOT use it for:
- Answering questions that can be resolved with a single decompiler query (e.g. "what does this function return?").
- Bulk-annotating an entire binary in one call. Annotate one function at a time.
- Modifying disassembly, patching bytes, or changing types. The annotator only renames identifiers and sets comments.

# Parameters

## `function_address` (required)
The effective address (EA) of the function to annotate. Must be a valid function entry point.

Acceptable forms:
- Hex string: `"0x140009050"`, `"0x14000905C"`.

If the address is invalid, is not the start of a function, or refers to a function that failed to decompile, the tool returns an error. Do not retry with the same address hoping it works — verify the address first using `get_function_by_address` or `get_function_by_name`.

Common mistakes to avoid:
- Passing an EA in the middle of a function. Use the function's *entry* EA.
- Passing an address from a data segment. Only code addresses inside functions work.
- Passing a stripped-down address like `"140009050"` without the `0x` prefix. Include the prefix or pass as int.

## `user_prompt` (optional)
Additional guidance for the annotator, tailored to what the user actually wants.

**Keep it focused.** The annotator already has strong default behavior (rename everything, comment where useful, verify the result). Do not restate the defaults; only add information the annotator wouldn't otherwise know.

Good use cases for `user_prompt`:
- Domain hints: `"This binary is a game engine; the function may be related to physics or rendering."`
- Known context: `"The caller of this function passes a decrypted config buffer."`
- Priority signals: `"Focus on the loop starting around offset 0x50 — the user suspects it's a hash function."`
- Naming conventions: `"Prefer Windows API convention (CamelCase). This is a Win32 binary."`

Bad use cases:
- Restating defaults: `"Please rename all variables and add comments."` — the annotator already does this.
- Over-specification: `"Rename v0 to buffer_size, v1 to counter, sub_X to init_crypto..."` — you're doing the annotator's job; let it decide.
- Long backstory: multi-paragraph descriptions of the binary's history dilute the actual guidance.

If you don't have specific guidance, omit the prompt entirely. An empty prompt is fine and often optimal.

Length guidance: 1-3 sentences. If your `user_prompt` exceeds 3 sentences, you're probably over-specifying.

# Behavior

The annotator will:
1. Fetch the pseudocode of the target function.
2. Recursively inspect callees when needed for context.
3. Rename all local variables, arguments, and any called sub-functions.
4. Set inline comments on non-obvious lines.
5. Verify the changes appear in the re-fetched pseudocode.
6. Return a summary of what it did.

The process may take several seconds to minutes depending on the function's complexity. The tool streams progress events; wait for the final result.

# What NOT to Do

- **Do not call this tool in a loop over many functions.** It is not designed for bulk operation. If the user wants many functions annotated, ask them to specify which ones or annotate the entry point and let the agent recursively annotate callees as needed.

- **Do not pass unrelated context in `user_prompt`.** Information about other functions, unrelated user goals, or long conversational history all reduce annotation quality.

# Handling Errors

If the tool returns an error:
- **"Invalid address"**: verify the address exists and is a function entry. Use `get_function_by_address` first.
- **"Failed to decompile"**: the function couldn't be decompiled. Do not retry. Report to the user; suggest they check for corrupt segments, missing types, or unresolved calls.
- **"Function not found"**: the name doesn't resolve. Try passing the address as hex instead of the symbolic name.
- **Silent completion with no changes**: the annotator ran but declared nothing to do. Rare; usually means the function is already well-annotated. Fetch the pseudocode to confirm.

Do not retry on errors that indicate malformed input. Fix the input, then call once.

# Examples

**User asks "annotate the main function"**:
annotate_function(function_address="main")
No `user_prompt` needed; default behavior is sufficient.

**User asks "look at the encryption routine at 0x140009050 — I think it's XOR-based"**:
annotate_function(

function_address="0x140009050",

user_prompt="Suspected XOR-based encryption. Focus on identifying the key derivation and mixing operations."

)
Short, focused prompt with useful domain hint.

**User asks "annotate that function I mentioned earlier"**:
Do not guess. Ask the user which function they mean and get a concrete address or name first.

**User asks "annotate all the functions in this binary"**:
Do not call the tool 500 times. Explain the tool is single-function; ask the user to prioritize (e.g., "which entry points matter most?") and annotate those individually.

# Verifying Results

After the tool returns, fetch the pseudocode of the annotated function to confirm the changes are visible:
get_function_pseudocode(function_name="<new name after annotation>")

Report the annotator's summary alongside the confirmed pseudocode to the user. This gives them confidence the annotations were actually applied, not just described.