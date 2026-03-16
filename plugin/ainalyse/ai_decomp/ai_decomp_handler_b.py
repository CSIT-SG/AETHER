import asyncio

import ida_kernwin
import idaapi

from .generator import run_ai_decomp_for_current_function_b
from .storage import load_ai_decomp
from .viewer import AI_DECOMP_VIEW_TITLE, g_ai_decomp_viewers, show_or_update_ai_decomp_tab
from ainalyse.async_manager import start_pipeline

class AIDecompHandlerB(ida_kernwin.action_handler_t):
    """Handler for 'AI Decompile from here (Prompt B)' action that uses the no-think prompt."""
    
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
        
        print(f"[AETHER] [AI Decomp B] Checking for existing AI decompilation for {func_name} at {func_addr}")
        
        # Show the AI decompilation tab immediately
        show_or_update_ai_decomp_tab(func_addr)
        
        # Check if AI decompilation already exists for this function
        existing_decomp = load_ai_decomp(func_addr)
        
        if existing_decomp:
            # Ask user if they want to regenerate
            if ida_kernwin.ask_yn(1, f"An existing AI decompilation was found for {func_name}.\nDo you want to regenerate it with Prompt B (variable renaming)?") != 1:
                print(f"[AETHER] [AI Decomp B] User chose not to regenerate existing AI decompilation.")
                return 1
        
        print(f"[AETHER] [AI Decomp B] Generating AI decompilation with Prompt B for {func_name} at {func_addr}")
        
        # Start AI decompilation in background thread
        async def ai_decomp_thread(config, func_addr):
            """(Worker Thread) Optimized async pipeline for AI Decompilation Prompt B."""
            from .. import validate_analysis_config # Ensure fresh import for the coroutine

            def _update_ui(error_text=None, is_timeout=False):
                """Sync helper to update the IDA viewer."""
                def sync_op():
                    viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
                    if viewer_instance:
                        viewer_instance.SetGenerating(False)
                        if is_timeout:
                            viewer_instance.SetError("AI decompilation (Prompt B) failed or timed out.\nPlease check that MCP server is running.")
                        elif error_text:
                            viewer_instance.SetError(error_text)
                ida_kernwin.execute_sync(sync_op, ida_kernwin.MFF_WRITE)

            try:
                # 1. Validation Step
                print("[AETHER] [AI Decomp B] Testing configuration...")
                try:
                    validation_success, validation_msg = await asyncio.wait_for(
                        validate_analysis_config(config), 
                        timeout=5.0
                    )
                    if not validation_success:
                        print(f"[AETHER] [AI Decomp B] Configuration validation failed: {validation_msg}")
                        _update_ui(error_text=f"Configuration Error: {validation_msg}")
                        return
                except asyncio.TimeoutError:
                    msg = "Connection to MCP server timed out. Is MCP server running? (Run 'ida-pro-mcp' command first)"
                    print(f"[AETHER] [AI Decomp B] Configuration validation failed: {msg}")
                    _update_ui(error_text=f"Configuration Error: {msg}")
                    return

                # 2. Execution Step
                try:
                    success = await asyncio.wait_for(
                        run_ai_decomp_for_current_function_b(config, func_addr), 
                        timeout=300.0
                    )
                    
                    if success:
                        print("[AETHER] [AI Decomp B] AI decompilation with Prompt B completed successfully.")
                        _update_ui()
                    else:
                        print("[AETHER] [AI Decomp B] AI decompilation with Prompt B failed or timed out.")
                        _update_ui(is_timeout=True)

                except asyncio.TimeoutError:
                    print("[AETHER] [AI Decomp B] AI decompilation timed out after 5 minutes")
                    _update_ui(is_timeout=True)

            except Exception as e:
                print(f"[AETHER] [AI Decomp B] Error during AI decompilation: {e}")
                import traceback
                traceback.print_exc()
                _update_ui(error_text=f"Error: {str(e)}")

        start_pipeline(ai_decomp_thread(config, func_addr))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET
