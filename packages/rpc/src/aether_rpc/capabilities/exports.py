import importlib

from aether_rpc.capabilities.base import Capability

# map exactly: capability name to module path relative to this package
# this will be dynamically loaded by the RPC server to register capabilities
EXPORTS: dict[str, str] = {
    "GetDataAtAddress": ".misc.get_data_at_address.get_data_at_address",
    "GetFunctionByAddress": ".function.get_function_by_address.get_function_by_address",
    "GetFunctionByName": ".function.get_function_by_name.get_function_by_name",
    "GetFunctionPseudocode": ".function.get_function_pseudocode.get_function_pseudocode",
    "GetLocalVariables": ".variables.get_local_variables.get_local_variables",
    "GetXrefsTo": ".variables.get_xrefs_to.get_xrefs_to",
    "GetStackVariableXrefs": ".variables.get_stack_variable_xrefs.get_stack_variable_xrefs",
    "RenameFunction": ".function.rename_function.rename_function",
    "RenameLocalVariable": ".variables.rename_local_variable.rename_local_variable",
    "ExecuteIDAPython": ".misc.execute_idapython.execute_idapython",
    "RefreshPseudocode": ".misc.refresh_pseudocode.refresh_pseudocode",
    "TakeSnapshot": ".misc.take_snapshot.take_snapshot",
    "GetFunctionsCalledRecursively": ".function.get_functions_called_recursively.get_functions_called_recursively",
    "GetStructIdByName": ".struct.get_struct_id_by_name.get_struct_id_by_name",
    "RenameStructField": ".struct.rename_struct_field.rename_struct_field",
    "DeleteStruct": ".struct.delete_struct.delete_struct",
    "CreateStruct": ".struct.create_struct.create_struct",
    "ChangeStructFieldSize": ".struct.change_struct_field_size.change_struct_field_size",
    "ChangeStructFieldType": ".struct.change_struct_field_type.change_struct_field_type",
    "GetStructInfo": ".struct.get_struct_info.get_struct_info",
    "RenameStruct": ".struct.rename_struct.rename_struct",
    "AddStructField": ".struct.add_struct_field.add_struct_field",
    "DeleteStructField": ".struct.delete_struct_field.delete_struct_field",
    "ListStructs": ".struct.list_structs.list_structs",
    "ApplyStruct": ".struct.apply_struct.apply_struct",
    "GetStructAtAddress": ".struct.get_struct_at_address.get_struct_at_address",
    "ValidateYaraRule": ".misc.validate_yara_rule.validate_yara_rule",
    "GetBinaryMetadata": ".misc.get_binary_metadata.get_binary_metadata",
    "ListFunctions": ".function.list_functions.list_functions",
    "SetInlineComment": ".comments.set_inline_comment.set_inline_comment",
    "SetSummaryComment": ".comments.set_summary_comment.set_summary_comment",
}


def load_capabilities() -> list[Capability]:
    """Dynamically load all capabilities from the EXPORTS mapping."""
    return [
        getattr(importlib.import_module(module_path, __package__), name)()
        for name, module_path in EXPORTS.items()
    ]
