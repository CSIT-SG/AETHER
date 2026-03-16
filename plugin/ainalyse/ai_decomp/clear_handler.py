import ida_kernwin

from .storage import clear_all_ai_decomp
from .viewer import AI_DECOMP_VIEW_TITLE, g_ai_decomp_viewers


class ClearAIDecompHandler(ida_kernwin.action_handler_t):
    """Handler for clearing all AI decompilations from storage."""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Confirm with user before clearing
        if ida_kernwin.ask_yn(0, "Are you sure you want to clear ALL AI decompilations?\n\nThis action cannot be undone.") != 1:
            return 1
        
        print("[AETHER] [AI Decomp] Clearing all AI decompilations...")
        
        # Clear from storage
        success = clear_all_ai_decomp()
        
        if success:
            # Update viewer if open
            viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
            if viewer_instance:
                viewer_instance.UpdateDisplay()
            
            ida_kernwin.info("All AI decompilations have been cleared successfully.")
            print("[AETHER] [AI Decomp] All AI decompilations cleared successfully")
        else:
            ida_kernwin.warning("Failed to clear AI decompilations. Check console for details.")
            print("[AETHER] [AI Decomp] Failed to clear AI decompilations")
        
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
