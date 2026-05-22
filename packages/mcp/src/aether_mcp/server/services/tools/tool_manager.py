from collections.abc import Callable
from typing import Any

# TODO: Just a placeholder to setup chatbot for calling functions, not finalized
# execute() can be used to run multiple tools at once, for example tools that just read from the binary and not renaming
# Since can take in just functions, could be used for different apps with different APIs
# Should probably isolate tool manager from tools import and stuff


class ToolManager:
    def __init__(self):
        self._registry: dict[str, Callable] = {}

    # TODO: Make register tool work for imports
    def register_tool(self, name: str) -> Callable:
        def decorator(func: Callable) -> Callable:
            self._registry[name] = func
            return func

        return decorator

    def execute(self, tool_name: str, args_list: list[Any]) -> Any:
        """
        Executes a registered tool by its name, passing a separate list of arguments.
        """
        tool_function = self._registry.get(tool_name)

        if not tool_function:
            return f"Error: Tool '{tool_name}' is not registered."

        try:
            # The '*' unpacks the list [0x401000, 16] into individual positional arguments
            return tool_function(*args_list)
        except TypeError as e:
            return f"Error: Invalid arguments for tool '{tool_name}'. Details: {e}"
        except Exception as e:
            return f"Error executing tool '{tool_name}': {str(e)}"
