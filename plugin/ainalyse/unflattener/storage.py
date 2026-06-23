from typing import Optional

import ida_kernwin
import idaapi

# --- Netnode Storage for AI Deobfuscations ---
NETNODE_AI_DEOBFS = "$ainalyse.ai_deobfs.v1"

def get_ai_deobfs_netnode():
    """Gets or creates the netnode for storing AI deobfuscations."""
    nn = idaapi.netnode(NETNODE_AI_DEOBFS, 0, True)
    return nn

def save_ai_deobfs(func_addr: str, deobfs_code: str):
    """Save AI deobfuscation for a function address."""
    # Use a container to hold the result
    result_container = {"success": False}
    
    def _save_sync():
        nn = get_ai_deobfs_netnode()
        try:
            nn.setblob(deobfs_code.encode('utf-8'), int(func_addr, 16), 'D')
            print(f"[AInalyse] [AI Unflatten] [Netnode] Saved AI deobfuscation to netnode for {func_addr} ({len(deobfs_code)} characters)")
            result_container["success"] = True
            return True
        except Exception as e:
            print(f"[AInalyse] [AI Unflatten] [Netnode] Error saving AI deobfuscation for {func_addr}: {e}")
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
        print(f"[AInalyse] [AI Unflatten] [Netnode] Save execute_sync failed: {e}")
        # Check container despite exception
        return result_container["success"]

def load_ai_deobfs(func_addr: str) -> Optional[str]:
    """Load AI deobfuscation for a function address."""
    # Use a container to hold the result since execute_sync has issues with return values
    result_container = {"data": None}
    def _load_sync():
        nn = get_ai_deobfs_netnode()
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
            print(f"[AInalyse] [AI Unflatten] [Netnode] Error loading AI deobfuscation for {func_addr}: {e}")
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
        print(f"[AInalyse] [AI Unflatten] [Netnode] Execute_sync failed: {e}")
        # Check if we got data in the container despite the exception
        if result_container["data"] is not None:
            return result_container["data"]
        return None
