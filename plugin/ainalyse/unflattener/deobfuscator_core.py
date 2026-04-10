from typing import Dict, Set

import ida_kernwin

from .storage import load_ai_deobfs, save_ai_deobfs
from .viewer import AI_DEOBFS_VIEW_TITLE, g_ai_deobfs_viewers

def check_and_save_new_deobfuscations(deobfuscations: Dict[str, str], already_saved: Set[str]) -> None:
    """Check for new deobfuscations and save them to netnode if not already saved."""
    for func_addr, deobfs_code in deobfuscations.items():
        should_save = False
        
        if func_addr not in already_saved:
            should_save = True
            already_saved.add(func_addr)
            print(f"[AInalyse] [AI Unflatten] [Real-time] Found new AI deobfuscation for {func_addr}")
        else:
            existing_deobfs = load_ai_deobfs(func_addr)
            if existing_deobfs and len(deobfs_code) > len(existing_deobfs) + 50:
                should_save = True
                print(f"[AInalyse] [AI Unflatten] [Real-time] Updated AI deobfuscation for {func_addr} ({len(existing_deobfs)} -> {len(deobfs_code)} chars)")
            elif not existing_deobfs:
                should_save = True
                print(f"[AInalyse] [AI Unflatten] [Real-time] Retrying save for {func_addr} (no existing data found)")
        
        if should_save:
            if save_ai_deobfs(func_addr, deobfs_code):
                print(f"[AInalyse] [AI Unflatten] [Real-time] Successfully saved AI deobfuscation for {func_addr}")
                
                def _update_viewer_for_addr():
                    viewer_instance = g_ai_deobfs_viewers.get(AI_DEOBFS_VIEW_TITLE)
                    if (viewer_instance and 
                        viewer_instance.current_func_addr and
                        viewer_instance.current_func_addr.lower() == func_addr.lower()):
                        viewer_instance.SetGenerating(False)
                        viewer_instance.UpdateDisplay()
                try:
                    ida_kernwin.execute_sync(_update_viewer_for_addr, ida_kernwin.MFF_WRITE)
                except Exception as e:
                    print(f"[AInalyse] [AI Unflatten] [Real-time] Error updating viewer: {e}")
            else:
                print(f"[AInalyse] [AI Unflatten] [Real-time] Failed to save AI deobfuscation for {func_addr}")