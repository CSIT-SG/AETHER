import asyncio

import ida_kernwin
import idaapi

from .generator import run_ai_decomp_for_functions
from .storage import load_ai_decomp
from ainalyse.async_manager import start_pipeline

class AIDecompSelectorHandler(ida_kernwin.action_handler_t):
    """Handler for 'Select functions for AI decompile' menu option."""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Import here to avoid circular imports
        from .. import load_config, create_default_config, show_config_error, run_async_in_ida, validate_analysis_config, CONFIG_FILE, validate_basic_config
        
        config = load_config()
        
        # Use basic validation first
        is_valid, error_msg = validate_basic_config(config)
        if not is_valid:
            ida_kernwin.warning(error_msg)
            return 1
        
        # Get current function
        try:
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func:
                ida_kernwin.warning("No function found at current location.")
                return 1
            
            func_addr = hex(func.start_ea)
            func_name = idaapi.get_func_name(func.start_ea)
        except:
            ida_kernwin.warning("Unable to get current function address.")
            return 1
        
        # Import here to avoid circular import
        from ..function_selection import FunctionSelectionDialog
        
        # Open function selection dialog
        dlg = FunctionSelectionDialog(func_name, func_addr, "Select Functions for AI Decompilation")
        
        if dlg.exec_():
            selected_functions = dlg.get_selected_functions()
            
            if not selected_functions:
                ida_kernwin.info("No functions selected.")
                return 1
            
            print(f"[AETHER] [AI Decomp] Selected {len(selected_functions)} functions for AI decompilation")
            
            # Check which functions already have AI decompilations
            functions_to_process = []
            existing_count = 0
            
            for func_info in selected_functions:
                existing_decomp = load_ai_decomp(func_info['address'])
                if existing_decomp:
                    existing_count += 1
                    print(f"[AETHER] [AI Decomp] Function {func_info['name']} already has AI decompilation, skipping")
                else:
                    functions_to_process.append(func_info)
            
            if existing_count > 0:
                ida_kernwin.info(f"Note: {existing_count} functions already have AI decompilations and will be skipped.\n{len(functions_to_process)} functions will be processed.")
            
            if not functions_to_process:
                ida_kernwin.info("All selected functions already have AI decompilations.")
                return 1
            
            # Start AI decompilation in background thread
            async def ai_decomp_thread(config, functions_to_process):
                try:
                    # Validate configuration first
                    validation_success, validation_msg = await validate_analysis_config(config)
                    if not validation_success:
                        ida_kernwin.execute_sync(
                            lambda: ida_kernwin.warning(f"Configuration validation failed:\n\n{validation_msg}"),
                            ida_kernwin.MFF_WRITE
                        )
                        return
                    
                    print(f"[AETHER] [AI Decomp] Starting AI decompilation for {len(functions_to_process)} functions...")
                    
                    # Run AI decompilation for selected functions
                    success = await run_ai_decomp_for_functions(config, functions_to_process)
                    
                    if success:
                        print("[AETHER] [AI Decomp] AI decompilation completed successfully for all selected functions.")
                        ida_kernwin.execute_sync(
                            lambda: ida_kernwin.info(f"AI decompilation completed for {len(functions_to_process)} functions."),
                            ida_kernwin.MFF_WRITE
                        )
                    else:
                        print("[AETHER] [AI Decomp] AI decompilation failed.")
                        ida_kernwin.execute_sync(
                            lambda: ida_kernwin.warning("AI decompilation failed. Check console for details."),
                            ida_kernwin.MFF_WRITE
                        )
                        
                except Exception as e:
                    print(f"[AETHER] [AI Decomp] Error during AI decompilation: {e}")
                    import traceback
                    traceback.print_exc()
                    ida_kernwin.execute_sync(
                        lambda: ida_kernwin.warning(f"AI decompilation error: {str(e)}"),
                        ida_kernwin.MFF_WRITE
                    )

            start_pipeline(ai_decomp_thread(config, functions_to_process))
        
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET
