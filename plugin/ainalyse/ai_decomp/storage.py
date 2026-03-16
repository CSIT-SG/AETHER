from typing import Optional

import ida_kernwin
import idaapi

# --- Netnode Storage for AI Decompilations ---
NETNODE_AI_DECOMP = "$ainalyse.ai_decomp.v1"

def get_ai_decomp_netnode():
    """Gets or creates the netnode for storing AI decompilations."""
    nn = idaapi.netnode(NETNODE_AI_DECOMP, 0, True)
    return nn

def save_ai_decomp(func_addr: str, decomp_code: str):
    """Save AI decompilation for a function address."""
    # Use a container to hold the result
    result_container = {"success": False}
    
    def _save_sync():
        nn = get_ai_decomp_netnode()
        try:
            nn.setblob(decomp_code.encode('utf-8'), int(func_addr, 16), 'D')
            print(f"[AETHER] [AI Decomp] [Netnode] Saved AI decompilation to netnode for {func_addr} ({len(decomp_code)} characters)")
            result_container["success"] = True
            return True
        except Exception as e:
            print(f"[AETHER] [AI Decomp] [Netnode] Error saving AI decompilation for {func_addr}: {e}")
            result_container["success"] = False
            return False
    
    # Try execute_sync
    try:
        sync_result = ida_kernwin.execute_sync(_save_sync, ida_kernwin.MFF_WRITE)
        
        # Use container result if available
        if result_container["success"]:
            return True
        
        # Fallback to sync_result
        return bool(sync_result) if sync_result is not None else False
        
    except Exception as e:
        print(f"[AETHER] [AI Decomp] [Netnode] Save execute_sync failed: {e}")
        # Check container despite exception
        return result_container["success"]

def load_ai_decomp(func_addr: str) -> Optional[str]:
    """Load AI decompilation for a function address."""
    # Use a container to hold the result since execute_sync has issues with return values
    result_container = {"data": None}
    
    def _load_sync():
        nn = get_ai_decomp_netnode()
        try:
            blob = nn.getblob(int(func_addr, 16), 'D')
            if blob:
                result = blob.decode('utf-8')
                result_container["data"] = result
                return result
            else:
                result_container["data"] = None
                return None
        except Exception as e:
            print(f"[AETHER] [AI Decomp] [Netnode] Error loading AI decompilation for {func_addr}: {e}")
            result_container["data"] = None
            return None
    
    # Try execute_sync
    try:
        sync_result = ida_kernwin.execute_sync(_load_sync, ida_kernwin.MFF_READ)
        
        # Use the container result regardless of what execute_sync returns
        if result_container["data"] is not None:
            return result_container["data"]
        
        # If container is empty but sync_result has data, use that
        if isinstance(sync_result, str) and sync_result:
            return sync_result
            
        return None
        
    except Exception as e:
        print(f"[AETHER] [AI Decomp] [Netnode] Execute_sync failed: {e}")
        # Check if we got data in the container despite the exception
        if result_container["data"] is not None:
            return result_container["data"]
        return None

def clear_all_ai_decomp():
    """Clear all AI decompilations from storage."""
    def _clear_sync():
        nn = get_ai_decomp_netnode()
        try:
            # Clear all data in the netnode
            nn.kill()
            print("[AETHER] [AI Decomp] [Netnode] Cleared all AI decompilations from storage")
            return True
        except Exception as e:
            print(f"[AETHER] [AI Decomp] [Netnode] Error clearing AI decompilations: {e}")
            return False
    
    # Try execute_sync
    try:
        result = ida_kernwin.execute_sync(_clear_sync, ida_kernwin.MFF_WRITE)
        return bool(result) if result is not None else False
    except Exception as e:
        print(f"[AETHER] [AI Decomp] [Netnode] Clear execute_sync failed: {e}")
        return False
