import json
import os
import sys
import traceback

from .tools import TOOL_REGISTRY

def get_tool_config_file_path():
    """Get the appropriate configuration file path based on platform."""
    if sys.platform == "win32":
        # Use AppData/Local on Windows
        appdata_local = os.environ.get('LOCALAPPDATA')
        if appdata_local:
            config_dir = os.path.join(appdata_local, "AETHER-IDA")
        else:
            # Fallback if LOCALAPPDATA is not set
            config_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "AETHER-IDA")
        
        # Create directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "tool_config.json")
    else:
        # Use the original location on non-Windows platforms
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "tool-config.json")

TOOL_CONFIG_FILE = get_tool_config_file_path()

def get_default_tool_config() -> dict:
    """
    Generates the default tool configuration based on the current TOOL_REGISTRY.
    All tools are enabled (True) by default.
    """
    default_config = {
        # Explicitly access the string value of the Enum object
        tool_name.value: True 
        for tool_name in TOOL_REGISTRY.keys()
    }
    return default_config

def create_tool_config_file(config_data: dict = None):
    """Creates the tool configuration file with the provided data or default data."""
    if config_data is None:
        config_data = get_default_tool_config()
        
    try:
        config_dir = os.path.dirname(TOOL_CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        
        with open(TOOL_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
            
        print(f"[AETHER] Created/Recreated tool config at {TOOL_CONFIG_FILE}")
        return True
    except Exception as e:
        print(f"[AETHER] Error creating tool config file: {e}")
        return False

def load_tool_config() -> dict:
    """
    Loads and validates the tool configuration. 
    Recreates the file if missing, corrupt, or toolset has changed.
    """
    
    current_tool_names = {tool_name.value for tool_name in TOOL_REGISTRY.keys()}
    
    # 1. Check if file is missing
    if not os.path.exists(TOOL_CONFIG_FILE):
        print("[AETHER] Tool config file missing. Creating default...")
        create_tool_config_file()
        return get_default_tool_config()
    
    try:
        # 2. Try to load the config
        with open(TOOL_CONFIG_FILE, "r", encoding="utf-8") as f:
            loaded_config = json.load(f)
            
        loaded_tool_names = set(loaded_config.keys())
        
        # 3. Validation: Check for consistency with TOOL_REGISTRY
        
        # Check if all tools in the registry exist in the config, AND vice-versa.
        # This handles added/removed/renamed tools.
        if loaded_tool_names != current_tool_names:
            print("[AETHER] Tool config mismatch (tools added/removed/renamed). Recreating...")
            return handle_mismatch(loaded_config, current_tool_names)
        
        # 4. Success: Return the loaded configuration
        print("[AETHER] Config Loaded")
        return loaded_config
        
    except Exception as e:
        # 5. Handle corruption or loading errors
        print(f"[AETHER] Error loading tool config ({e}). File corrupt or format invalid. Deleting and recreating default.")
        logging.exception('Unhandled exception')
        
        # Delete corrupt file (as requested)
        try:
            os.remove(TOOL_CONFIG_FILE)
        except Exception as e_del:
            print(f"[AETHER] Error deleting corrupt tool config: {e_del}")
            
        create_tool_config_file()
        return get_default_tool_config()

def handle_mismatch(loaded_config: dict, current_tool_names: set) -> dict:
    """
    Handles when the tools in the file don't match the registry. 
    Preserves settings for existing tools, adds new tools as True, and removes obsolete tools.
    """
    new_config = {}
    
    # Keep old settings for existing tools
    for tool_name in current_tool_names:
        if tool_name in loaded_config:
            # Preserve the existing true/false setting
            new_config[tool_name] = loaded_config[tool_name]
        else:
            # New tool, enable it by default
            new_config[tool_name] = True
            
    # Write the clean, updated config back to the file
    create_tool_config_file(new_config)
    
    return new_config

def save_tool_config(updated_tool_config: dict):
    """
    Persists the updated tool configuration dictionary to the JSON file.
    """
    global TOOL_CONFIG # Ensure we update the global variable in memory
    
    try:
        # 1. Update the in-memory global config
        TOOL_CONFIG.clear()
        TOOL_CONFIG.update(updated_tool_config)

        # 2. Write the changes to the file
        config_dir = os.path.dirname(TOOL_CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        
        with open(TOOL_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(TOOL_CONFIG, f, indent=2)
            
        print("[AETHER] Tool configuration saved successfully")
        return True
    except Exception as e:
        print(f"[AETHER] ERROR: Could not save tool configuration to file: {e}")
        return False

# Initialize the global configuration when the module is imported
TOOL_CONFIG = load_tool_config()