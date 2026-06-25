import importlib
from typing import Any

_IMPORTS: dict[str, str] = {
    "GetDataAtAddress": ".get_data_at_address",
    "GetFunctionByAddress": ".get_function_by_address",
    "GetFunctionByName": ".get_function_by_name",
    "GetFunctionPseudocode": ".get_function_pseudocode",
    "GetLocalVariables": ".get_local_variables",
    "GetXrefsTo": ".get_xrefs_to",
    "RenameFunction": ".rename_function",
    "RenameLocalVariable": ".rename_local_variable",
    "SetComment": ".set_comment",
}

# ONLY export the capability classes, never submodules or helper functions.
# The service layer will dynamically discover capabilities by looking for
# these names in the package namespace.
__all__ = list(_IMPORTS.keys())  # type: ignore


def __getattr__(name: str) -> Any:
    """Lazy-load capability classes on first attribute access.

    Importing this package does not pull in IDA-dependent modules; each
    capability module is loaded only when its class is actually accessed.

    Args:
        name: The attribute being accessed on this package.

    Returns:
        The capability class.

    Raises:
        AttributeError: If ``name`` is not a known capability.
    """
    if name in _IMPORTS:
        module = importlib.import_module(_IMPORTS[name], __package__)
        attr = getattr(module, name)
        globals()[name] = attr  # cache so subsequent lookups skip __getattr__
        return attr
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
