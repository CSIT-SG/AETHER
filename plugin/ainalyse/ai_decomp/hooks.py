import ida_hexrays

from .viewer import AI_DECOMP_VIEW_TITLE, g_ai_decomp_viewers, remove_scroll_hooks, show_or_update_ai_decomp_tab


# --- Hexrays Hook for Auto-updating the Tab ---
class AIDecompHexraysHooks(ida_hexrays.Hexrays_Hooks):
    """Hooks into Hex-Rays events to detect when the user changes functions."""
    
    def switch_pseudocode(self, vdui):
        """Called when a pseudocode view is open or the user switches functions."""
        func_ea = vdui.cfunc.entry_ea
        func_addr = hex(func_ea)

        # Only update if our AI decomp viewer tab actually exists
        if AI_DECOMP_VIEW_TITLE in g_ai_decomp_viewers:
            show_or_update_ai_decomp_tab(func_addr)
        return 0

# --- Global hooks instance ---
_ai_decomp_hooks = None

def install_ai_decomp_hooks():
    """Install the Hexrays hooks for AI decompilation."""
    global _ai_decomp_hooks
    if not _ai_decomp_hooks and ida_hexrays.init_hexrays_plugin():
        _ai_decomp_hooks = AIDecompHexraysHooks()
        _ai_decomp_hooks.hook()
        print("[AETHER] [AI Decomp] Installed Hexrays hooks for auto-updating.")

def remove_ai_decomp_hooks():
    """Remove the Hexrays hooks for AI decompilation."""
    global _ai_decomp_hooks
    if _ai_decomp_hooks:
        _ai_decomp_hooks.unhook()
        _ai_decomp_hooks = None
        print("[AETHER] [AI Decomp] Removed Hexrays hooks.")
    
    # Also remove scroll hooks
    remove_scroll_hooks()
