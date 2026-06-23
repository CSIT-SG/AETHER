import json
import os
import sys
import traceback

from ainalyse import get_data_directory
from ainalyse.chatbot.chatbot_ida.toolset import CHATBOT_TOOL_REGISTRY as TOOL_REGISTRY


def get_tool_config_file_path():
    if sys.platform == "win32":
        appdata_local = os.environ.get("LOCALAPPDATA")
        if appdata_local:
            config_dir = os.path.join(appdata_local, "AETHER-IDA")
        else:
            config_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "AETHER-IDA")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "chatbot-tool-config.json")
    return os.path.join(get_data_directory(), "chatbot-tool-config.json")


TOOL_CONFIG_FILE = get_tool_config_file_path()


def get_default_tool_config() -> dict:
    return {tool_name.value: True for tool_name in TOOL_REGISTRY.keys()}


def create_tool_config_file(config_data: dict | None = None):
    if config_data is None:
        config_data = get_default_tool_config()
    try:
        config_dir = os.path.dirname(TOOL_CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        with open(TOOL_CONFIG_FILE, "w", encoding="utf-8") as handle:
            json.dump(config_data, handle, indent=2)
        print(f"[AETHER] Created/Recreated tool config at {TOOL_CONFIG_FILE}")
        return True
    except Exception as exc:
        print(f"[AETHER] Error creating tool config file: {exc}")
        return False


def handle_mismatch(loaded_config: dict, current_tool_names: set) -> dict:
    new_config = {}
    for tool_name in current_tool_names:
        new_config[tool_name] = loaded_config.get(tool_name, True)
    create_tool_config_file(new_config)
    return new_config


def load_tool_config() -> dict:
    current_tool_names = {tool_name.value for tool_name in TOOL_REGISTRY.keys()}
    if not os.path.exists(TOOL_CONFIG_FILE):
        print("[AETHER] Tool config file missing. Creating default...")
        create_tool_config_file()
        return get_default_tool_config()
    try:
        with open(TOOL_CONFIG_FILE, "r", encoding="utf-8") as handle:
            loaded_config = json.load(handle)
        loaded_tool_names = set(loaded_config.keys())
        if loaded_tool_names != current_tool_names:
            print("[AETHER] Tool config mismatch (tools added/removed/renamed). Recreating...")
            return handle_mismatch(loaded_config, current_tool_names)
        print("[AETHER] Config Loaded")
        return loaded_config
    except Exception as exc:
        print(f"[AETHER] Error loading tool config ({exc}). File corrupt or format invalid. Deleting and recreating default.")
        traceback.print_exc()
        try:
            os.remove(TOOL_CONFIG_FILE)
        except Exception as delete_exc:
            print(f"[AETHER] Error deleting corrupt tool config: {delete_exc}")
        create_tool_config_file()
        return get_default_tool_config()


def save_tool_config(updated_tool_config: dict):
    global TOOL_CONFIG
    try:
        TOOL_CONFIG.clear()
        TOOL_CONFIG.update(updated_tool_config)
        config_dir = os.path.dirname(TOOL_CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        with open(TOOL_CONFIG_FILE, "w", encoding="utf-8") as handle:
            json.dump(TOOL_CONFIG, handle, indent=2)
        print("[AETHER] Tool configuration saved successfully")
        return True
    except Exception as exc:
        print(f"[AETHER] ERROR: Could not save tool configuration to file: {exc}")
        return False


TOOL_CONFIG = load_tool_config()
