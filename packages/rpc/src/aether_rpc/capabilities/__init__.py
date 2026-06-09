from .get_function_by_address import GetFunctionByAddress
from .get_function_by_name import GetFunctionByName
from .rename_function import RenameFunction
from .rename_local_variable import RenameLocalVariable
from .set_comment import SetComment

# ONLY export the capability classes, never submodules or helper functions
# the service layer will dynamically discover capabilities by looking for these names in the package namespace
__all__ = [
    "SetComment",
    "RenameLocalVariable",
    "GetFunctionByAddress",
    "GetFunctionByName",
    "RenameFunction",
]
