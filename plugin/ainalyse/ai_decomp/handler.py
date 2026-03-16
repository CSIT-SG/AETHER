import asyncio

import ida_kernwin
import idaapi

from .generator import run_ai_decomp_for_current_function
from .storage import load_ai_decomp
from .viewer import AI_DECOMP_VIEW_TITLE, g_ai_decomp_viewers, show_or_update_ai_decomp_tab
from ainalyse.async_manager import start_pipeline

class AIDecompHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Import here to avoid circular imports
        from .. import (
            load_config,
            run_async_in_ida,
            validate_analysis_config,
            validate_basic_config,
        )
        
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
        
        print(f"[AETHER] [AI Decomp] Checking for existing AI decompilation for {func_name} at {func_addr}")
        
        # Show the AI decompilation tab immediately
        show_or_update_ai_decomp_tab(func_addr)
        
        # Check if AI decompilation already exists for this function
        existing_decomp = load_ai_decomp(func_addr)
        
        if existing_decomp:
            print(f"[AETHER] [AI Decomp] Found existing AI decompilation for {func_name} at {func_addr} ({len(existing_decomp)} characters). No need to regenerate.")
            return 1
        
        print(f"[AETHER] [AI Decomp] No existing AI decompilation found. Generating new AI decompilation for {func_name} at {func_addr}")
        
        # Start AI decompilation in background thread only if no existing data
        async def ai_decomp_thread(config, func_addr):
            try:
                # Validate configuration first with shorter timeout and non-blocking approach
                # 1. Validation Step
                print("[AETHER] [AI Decomp] Testing configuration...")
                try:
                    success, msg = await asyncio.wait_for(
                        validate_analysis_config(config), 
                        timeout=5.0
                    )
                    if not success:
                        self._update_viewer_ui(error=f"Configuration Error: {msg}")
                        return
                except asyncio.TimeoutError:
                    self._update_viewer_ui(error="Connection to MCP server timed out. Is MCP server running? (Run 'ida-pro-mcp' command first)")
                    return
                
                # 2. Execution Step
                try:
                    # Native await with 5-minute timeout
                    success = await asyncio.wait_for(
                        run_ai_decomp_for_current_function(config, func_addr),
                        timeout=300.0
                    )
                    if not success:
                        self._update_viewer_ui(error="AI decompilation failed or timed out.")
                
                except asyncio.TimeoutError:
                    print("[AETHER] [AI Decomp] AI decompilation timed out after 5 minutes")
                    self._update_viewer_ui(error="AI decompilation timed out.")

            except Exception as e:
                print(f"[AETHER] [AI Decomp] Error during AI decompilation: {e}")
                import traceback
                traceback.print_exc()
                self._update_viewer_ui(error=f"Error: {str(e)}")
            
            

        start_pipeline(ai_decomp_thread(config, func_addr))
        return 1
    
    def _update_viewer_ui(self, error=None, generating=False):
        """Helper to thread-safely update the IDA Viewer."""
        def sync_op():
            viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
            if viewer_instance:
                viewer_instance.SetGenerating(generating)
                if error:
                    viewer_instance.SetError(error)

        ida_kernwin.execute_sync(sync_op, ida_kernwin.MFF_WRITE)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET
