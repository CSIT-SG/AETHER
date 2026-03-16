import re
from typing import Any, Dict, List


def parse_tool_calls(response_text: str) -> List[Dict[str, Any]]:
    """
    Parses a string containing tool calls based on the specified format.

    The format is:
    ```tool_name
    arg1|arg2|arg3
    arg1_1|arg2_1|arg3_1
    ```

    Args:
        response_text: The string response from the LLM.

    Returns:
        A list of dictionaries, where each dictionary represents a single
        tool call with 'tool_name' and 'args' keys.
    """
    parsed_calls = []
    # Find all ```...``` blocks
    blocks = re.findall(r"```(.*?)```", response_text, re.DOTALL)

    for block in blocks:
        if block.startswith('\n'):
            continue
        lines = block.strip().split('\n')
        if not lines:
            continue

        tool_name = lines[0].strip()
        arg_lines = lines[1:]

        if not arg_lines:
            # This handles cases like ```list_functions``` with no argument lines
            parsed_calls.append({"tool_name": tool_name, "args": []})
            continue

        for line in arg_lines:
            line = line.strip()
            if not line:
                # This handles cases with a blank line inside the block,
                # which we can treat as a no-arg call.
                parsed_calls.append({"tool_name": tool_name, "args": []})
                continue

            args = [arg.strip() for arg in line.split('|')]
            parsed_calls.append({
                "tool_name": tool_name,
                "args": args
            })

    return parsed_calls

if __name__ == '__main__':
    # Example usage for testing
    test_string = """
I will now call some tools.

```add_action_plan
My Plan|Task 1, Task 2
```

```add_task_to_plan
0|Do the first thing
0|Do the second thing|-1
```

Then I will list the functions.
```list_functions

```

And finally, get some pseudocode.
```get_function_pseudocode
main
sub_12345
```
    """
    
    parsed = parse_tool_calls(test_string)
    import json
    print(json.dumps(parsed, indent=2))
    
        # Expected output:
        # [
        #   {
        #     "tool_name": "add_action_plan",
        #     "args": [
        #       "My Plan",
        #       "Task 1, Task 2"
        #     ]
        #   },
        #   {
        #     "tool_name": "add_task_to_plan",
        #     "args": [
        #       "0",
        #       "Do the first thing"
        #     ]
        #   },
        #   {
        #     "tool_name": "add_task_to_plan",
        #     "args": [
        #       "0",
        #       "Do the second thing",
        #       "-1"
        #     ]
        #   },
        #   {
        #     "tool_name": "list_functions",
        #     "args": []
        #   },
        #   {
        #     "tool_name": "get_function_pseudocode",
        #     "args": [
        #       "main"
        #     ]
        #   },
        #   {
        #     "tool_name": "get_function_pseudocode",
        #     "args": [
        #       "sub_12345"
        #     ]
        #   }
        # ]
    
