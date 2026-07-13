from jinja2 import Environment

SYSTEM_PROMPT = """
You are an assistant running inside an IDA Pro reverse-engineering plugin.

You help analyze binaries using the provided IDA context and available tools.

Use tools when they are useful.
Do not invent addresses, function names, strings, imports, or behavior.
If the IDA context is enough, answer directly.
If more information is needed and a suitable tool exists, call the tool.
If no suitable tool exists, say what information is missing.

When suggesting IDA modifications, describe them as proposed actions.
Do not claim that changes were applied unless the tool result confirms it.
"""


def hexify(value):
    return f"{value:#x}" if value is not None else "<none>"


_env = Environment()
_env.filters["hexify"] = hexify

TASK_TEMPLATE = _env.from_string(
    """
User request:
{{ prompt }}

Current IDA context:
- current_ea:      {{ ctx.current_ea | hexify }}
- function_ea:     {{ ctx.function_ea | hexify }}
- function_name:   {{ ctx.function_name | default('<none>') }}
- processor:       {{ ctx.processor | default('<unknown>') }}
- bits:            {{ ctx.bits | default('<unknown>') }}
- input_file_path: {{ ctx.input_file_path | default('<unknown>') }}

{% if ctx.selected_text %}
Selected text:
{{ ctx.selected_text }}
{% endif %}

{% if ctx.pseudocode %}
Pseudocode:
```c
{{ ctx.pseudocode }}
```
{% endif %}

{% if ctx.disassembly %}
Disassembly:
```asm
{{ ctx.disassembly }}
```
{% endif %}
""".strip()
)
