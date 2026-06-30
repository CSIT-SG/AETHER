# map exactly: capability name to module name
# this will be dynamically loaded by the RPC server to register capabilities
EXPORTS: dict[str, str] = {
    "GetDataAtAddress": ".get_data_at_address",
    "GetFunctionByAddress": ".get_function_by_address",
    "GetFunctionByName": ".get_function_by_name",
    "GetFunctionPseudocode": ".get_function_pseudocode",
    "GetLocalVariables": ".get_local_variables",
    "GetXrefsTo": ".get_xrefs_to",
    "RenameFunction": ".rename_function",
    "RenameLocalVariable": ".rename_local_variable",
    "SetComment": ".set_comment",
    "ExecuteIDAPython": ".execute_idapython",
    "RefreshPseudocode": ".refresh_pseudocode",
    "TakeSnapshot": ".take_snapshot",
    "CollectFunctionsWithDefaultCriteria": ".collect_functions_with_default_criteria",
}
