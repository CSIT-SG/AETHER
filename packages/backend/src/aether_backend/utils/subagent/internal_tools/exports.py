import importlib

EXPORTS: dict[str, str] = {
    "get_data_at_address": ".get_data_at_address",
    "get_function_pseudocode": ".get_function_pseudocode",
    "get_local_variables": ".get_local_variables",
    "rename_function": ".rename_function",
    "rename_local_variable": ".rename_local_variable",
    "set_comment": ".set_comment",
}


def load_tools() -> None:
    """Import each tool module to trigger their @registry.tag decorators.

    Each module imports `registry` from `.tags` and decorates its function,
    which registers the tool. We only need to import the modules; we don't
    need to access any attribute on them.
    """
    for module_path in EXPORTS.values():
        importlib.import_module(module_path, __package__)