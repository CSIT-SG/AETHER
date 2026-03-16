"""
AETHER package - shared functions and utilities.
"""

import asyncio
import json
import os
import sys
import time
from copy import deepcopy
from urllib.parse import urlparse

import ida_kernwin
import idaapi
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from .async_manager import run_async_in_ida  # Re-export for backward compatibility

# --- Internal Imports ---
from .ssl_helper import create_openai_client_with_custom_ca

# Extra options prompt
PROMPT_ANNOTATOR_OPTIONS = os.path.join(os.path.dirname(__file__), "prompts/annotator-comment-options.txt")

# Re-export run_async_in_ida for backward compatibility
__all__ = ['run_async_in_ida']


# --- Config ---
def get_config_file_path():
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
        return os.path.join(config_dir, "config.json")
    else:
        # Use the original location on non-Windows platforms
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "ainalyse-config.json")

CONFIG_FILE = get_config_file_path()

DEFAULT_CONFIG = {
    "OPENAI_API_KEY": "",
    "OPENAI_MODEL": "qwen/qwen3-coder",
    "OPENAI_BASE_URL": "https://openrouter.ai/api/v1",
    "MCP_SERVER_URL": "http://127.0.0.1:8744/sse",
    "MAX_ITERATIONS": 5,
    "GATHERER_MODEL": "",  # Falls back to OPENAI_MODEL if empty
    "ANNOTATOR_MODEL": "",  # Falls back to OPENAI_MODEL if empty
    "AI_DECOMP_MODEL": "",  # Falls back to OPENAI_MODEL if empty
    "SINGLE_ANALYSIS_MODEL": "",  # Falls back to OPENAI_MODEL if empty
    "STRUCT_CREATOR_MODEL": "",  # Falls back to OPENAI_MODEL if empty
    "ANNOTATOR_MAX_TOKENS": 30000,
    "CHATBOT_MAX_TOKENS": 65536,
    "OPENAI_EXTRA_BODY": {},
    "CUSTOM_CA_CERT_PATH": "",
    "CLIENT_CERT_PATH": "",
    "CLIENT_KEY_PATH": "",
    "MODEL_LIST": {
        "Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder",
        "OpenAI: gpt-oss-120b": "openai/gpt-oss-120b",
        "Qwen: Qwen3 Next 80B A3B Instruct": "qwen/qwen3-next-80b-a3b-instruct"
    },
    "USE_DESC": True,
    "USE_COMMENTS": True,
    "RENAME_VARS": True,
    "RENAME_FUNCS": True,
    "RENAME_FILTER_ENABLED": True,
    "COMMENT_EVERY_LINE": False
}

MODEL_CONFIG_KEYS = (
    "OPENAI_MODEL",
    "GATHERER_MODEL",
    "ANNOTATOR_MODEL",
    "AI_DECOMP_MODEL",
    "SINGLE_ANALYSIS_MODEL",
    "STRUCT_CREATOR_MODEL",
)

def create_default_config():
    """Create default config file if it doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        try:
            # Ensure the directory exists (especially important for Windows AppData path)
            config_dir = os.path.dirname(CONFIG_FILE)
            os.makedirs(config_dir, exist_ok=True)
            
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"[AETHER] Created default config file at {CONFIG_FILE}")
        except Exception as e:
            print(f"[AETHER] Error creating config file: {e}")

def _write_config_file(config: dict) -> bool:
    """Write configuration to disk."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"[AETHER] Error saving config file: {e}")
        return False

def _validate_value_against_default(key: str, value, default_value, model_options: set[str]) -> str | None:
    """Return an error string when value is invalid, otherwise None."""
    expected_type = str if default_value == "" else type(default_value)

    if expected_type is bool:
        if not isinstance(value, bool):
            return f"Invalid item '{key}': expected bool"
        return None

    if expected_type is int:
        if not isinstance(value, int) or isinstance(value, bool):
            return f"Invalid item '{key}': expected int"
        if default_value > 0 and value <= 0:
            return f"Invalid item '{key}': expected integer > 0"
        return None

    if expected_type is str:
        if not isinstance(value, str):
            return f"Invalid item '{key}': expected string"
        return None

    if expected_type is dict:
        if not isinstance(value, dict):
            return f"Invalid item '{key}': expected object"

        if key == "MODEL_LIST":
            if not value:
                return "Invalid item 'MODEL_LIST': must not be empty"
            for display_name, model_id in value.items():
                if not isinstance(display_name, str) or not display_name.strip():
                    return "Invalid item 'MODEL_LIST': display names must be non-empty strings"
                if not isinstance(model_id, str) or not model_id.strip():
                    return "Invalid item 'MODEL_LIST': model IDs must be non-empty strings"
        return None

    return None

def _get_model_options(config: dict) -> set[str]:
    """Extract valid model IDs from MODEL_LIST, with default fallback."""
    model_list_value = config.get("MODEL_LIST", DEFAULT_CONFIG["MODEL_LIST"])
    if not isinstance(model_list_value, dict):
        model_list_value = DEFAULT_CONFIG["MODEL_LIST"]

    return {
        model_id.strip()
        for model_id in model_list_value.values()
        if isinstance(model_id, str) and model_id.strip()
    }

def get_config_validation_issues(config) -> list[str]:
    """Validate config keys and values without mutating config."""
    issues: list[str] = []

    if not isinstance(config, dict):
        return ["Configuration root must be a JSON object"]

    default_keys = set(DEFAULT_CONFIG.keys())
    config_keys = set(config.keys())

    for key in sorted(config_keys - default_keys):
        issues.append(f"Invalid key '{key}'")

    for key in sorted(default_keys - config_keys):
        issues.append(f"Missing key '{key}'")

    model_options = _get_model_options(config)

    for key, default_value in DEFAULT_CONFIG.items():
        if key not in config:
            continue

        value = config[key]
        value_error = _validate_value_against_default(key, value, default_value, model_options)
        if value_error:
            issues.append(value_error)
            continue

        if key in MODEL_CONFIG_KEYS and value:
            if value not in model_options:
                issues.append(f"Invalid item '{key}': '{value}' is not in MODEL_LIST options")

    return issues

def sanitize_config(config) -> tuple[dict, list[str]]:
    """Return sanitized config and the list of detected issues."""
    sanitized = deepcopy(DEFAULT_CONFIG)
    issues = get_config_validation_issues(config)

    if not isinstance(config, dict):
        populate_missing_models(sanitized, save_if_updated=False)
        return sanitized, issues

    model_options = _get_model_options(config)

    for key, default_value in DEFAULT_CONFIG.items():
        if key not in config:
            continue

        value = config[key]
        value_error = _validate_value_against_default(key, value, default_value, model_options)
        if value_error:
            continue

        if key in MODEL_CONFIG_KEYS and value and value not in model_options:
            continue

        sanitized[key] = deepcopy(value)

    populate_missing_models(sanitized, save_if_updated=False)
    return sanitized, issues

def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            raw_cfg = json.load(f)
    except Exception:
        raw_cfg = deepcopy(DEFAULT_CONFIG)

    sanitized_cfg, issues = sanitize_config(raw_cfg)
    if issues:
        _write_config_file(sanitized_cfg)

    return sanitized_cfg

def populate_missing_models(config: dict, save_if_updated: bool = True) -> bool:
    """Auto-populate missing model configurations from OPENAI_MODEL if available."""
    openai_model = config.get("OPENAI_MODEL", "")
    if not openai_model:
        return False  # Can't populate if OPENAI_MODEL is not set
    
    updated = False
    
    for model_key in MODEL_CONFIG_KEYS:
        if model_key == "OPENAI_MODEL":
            continue
        if not config.get(model_key):
            config[model_key] = openai_model
            print(f"[AETHER] Auto-populated {model_key} with '{openai_model}'")
            updated = True
    
    # Save the updated config if any changes were made
    if updated and save_if_updated:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            print("[AETHER] Updated configuration saved with auto-populated models")
        except Exception as e:
            print(f"[AETHER] Warning: Could not save updated config: {e}")
    
    return updated

def save_config(config):
    """Save config to the global config file."""
    sanitized_config, issues = sanitize_config(config)
    if issues:
        print("[AETHER] Following configuration issues were auto-corrected during save:")
        for issue in issues:
            print(f"[AETHER] - Returned {issue} to default")

    return _write_config_file(sanitized_config)

def show_config_error():
    """Show error dialog about missing config."""
    msg = f"""AETHER configuration file not found or invalid.

Please edit the configuration file at:
{CONFIG_FILE}

At minimum, you need to set your OPENAI_API_KEY and all models.

A default configuration has been created for you."""
    ida_kernwin.warning(msg)

def get_data_directory():
    """Get the appropriate data directory path based on platform."""
    if sys.platform == "win32":
        # Use AppData/Local on Windows
        appdata_local = os.environ.get('LOCALAPPDATA')
        if appdata_local:
            data_dir = os.path.join(appdata_local, "AETHER-IDA")
        else:
            # Fallback if LOCALAPPDATA is not set
            data_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "AETHER-IDA")
        
        # Create directory if it doesn't exist
        os.makedirs(data_dir, exist_ok=True)
        return data_dir
    else:
        # Use the original location on non-Windows platforms (in ainalyse directory)
        return os.path.dirname(__file__)

# --- Netnode Storage for Analysis History and Custom Prompts ---
NETNODE_NAME = "$ainalyse.analysis_history.v1"
NETNODE_PROMPTS = "$ainalyse.custom_prompts.v1"

def get_history_netnode():
    """Gets or creates the netnode for storing analysis history."""
    nn = idaapi.netnode(NETNODE_NAME, 0, True)
    return nn

def get_prompts_netnode():
    """Gets or creates the netnode for storing custom prompts."""
    nn = idaapi.netnode(NETNODE_PROMPTS, 0, True)
    return nn

def save_custom_prompts(gatherer_prompt: str, annotator_prompt: str):
    """Save custom prompts to netnode."""
    nn = get_prompts_netnode()
    try:
        data = {"gatherer": gatherer_prompt, "annotator": annotator_prompt}
        json_string = json.dumps(data)
        nn.setblob(json_string.encode('utf-8'), 0, 'B')
        return True
    except Exception as e:
        print(f"[AETHER] Error saving custom prompts: {e}")
        return False

def load_custom_prompts():
    """Load custom prompts from netnode."""
    nn = get_prompts_netnode()
    blob = nn.getblob(0, 'B')
    if not blob:
        return "", ""
    try:
        data = json.loads(blob.decode('utf-8'))
        return data.get("gatherer", ""), data.get("annotator", "")
    except Exception as e:
        print(f"[AETHER] Error loading custom prompts: {e}")
        return "", ""

# --- Analysis History Functions ---
def read_analysis_history():
    """Reads the analysis history from the netnode."""
    nn = get_history_netnode()
    blob = nn.getblob(0, 'B')
    if not blob:
        return []
    try:
        return json.loads(blob.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("[AETHER] Error: Could not decode analysis history from netnode.")
        return []

def write_analysis_history(history):
    """Writes the analysis history to the netnode."""
    nn = get_history_netnode()
    try:
        json_string = json.dumps(history, indent=2)
        nn.setblob(json_string.encode('utf-8'), 0, 'B')
        return True
    except TypeError:
        print("[AETHER] Error: Could not serialize analysis history to JSON.")
        return False

def add_analysis_entry(gatherer_output, annotator_output, starting_function, gatherer_prompt="", annotator_prompt="", structured_data=None):
    """Adds a new analysis entry to the history."""
    # Use the synchronous functions directly since they must run on main thread anyway
    def _add_entry_sync():
        history = read_analysis_history()
        entry = {
            "timestamp": time.time(),
            "starting_function": starting_function,
            "gatherer_output": gatherer_output,
            "annotator_output": annotator_output,
            "gatherer_prompt": gatherer_prompt,
            "annotator_prompt": annotator_prompt,
            "commands": structured_data
        }
        history.append(entry)
        return write_analysis_history(history)
    
    # Execute on main thread
    return ida_kernwin.execute_sync(_add_entry_sync, ida_kernwin.MFF_WRITE)


def get_current_function_name():
    """Get the name of the currently selected function in IDA."""
    try:
        ea = ida_kernwin.get_screen_ea()
        func = idaapi.get_func(ea)
        if func:
            return idaapi.get_func_name(func.start_ea)
        return "unknown"
    except:
        return "unknown"

async def test_mcp_connection(server_url: str) -> tuple[bool, str]:
    """Test MCP server connection and metadata retrieval."""
    if urlparse(server_url).scheme not in ("http", "https"):
        return False, "Invalid MCP server URL - must start with http:// or https://"
    
    try:
        # Test connection with timeout - use the original working pattern
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                
                # Test metadata retrieval
                try:
                    from .gatherer import mcp_get_tool_text_content
                    metadata = await mcp_get_tool_text_content(session, "get_metadata")
                    if metadata and "Connection refused" not in metadata:
                        print(f"[AETHER] [Test] Retrieved metadata: {metadata[:200]}...")  # Print first 200 chars
                        return True, f"Successfully connected to MCP server and retrieved IDB metadata:\n{metadata[:500]}..."
                        
                    return False, "Connected to MCP server but could not retrieve IDB metadata. Please check that IDA Pro MCP plugin is installed and running (Ctrl+Alt+M)"
                except Exception as e:
                    error_msg = str(e)
                    if "Connection refused" in error_msg:
                        return False, f"Connected to MCP server, but MCP server cannot connect to IDA Pro. Please ensure:\n1. IDA Pro MCP plugin is installed (Ctrl+Alt+M)\n2. IDA Pro MCP plugin is running and listening\n3. No firewall is blocking the connection\n\nError: {error_msg}"
                    else:
                        return False, f"Connected to MCP server but metadata test failed: {error_msg}. Please check IDA Pro MCP plugin installation and status."
                    
    except asyncio.TimeoutError:
        return False, f"Connection timeout to MCP server. Please ensure server is running with: ida-pro-mcp --transport {server_url}"
    except Exception as e:
        return False, f"Failed to connect to MCP server: {str(e)}. Please ensure server is running with: ida-pro-mcp --transport {server_url}"

async def validate_analysis_config(config: dict) -> tuple[bool, str]:
    """Validate configuration before running analysis."""
    # Test MCP connection
    mcp_success, mcp_msg = await test_mcp_connection(config["MCP_SERVER_URL"])
    if not mcp_success:
        return False, mcp_msg
    
    # Test OpenAI API
    if not config.get("OPENAI_API_KEY"):
        return False, "OPENAI_API_KEY is not set in configuration"
    
    try:        
        custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
        if custom_ca_cert_path:
            if not os.path.exists(custom_ca_cert_path):
                return False, f"Custom CA certificate file not found at: {custom_ca_cert_path}"
        
        client_cert_path = config.get("CLIENT_CERT_PATH", "")
        client_key_path = config.get("CLIENT_KEY_PATH", "")
        if client_cert_path or client_key_path:
            if not (client_cert_path and client_key_path):
                return False, "Both CLIENT_CERT_PATH and CLIENT_KEY_PATH must be provided for mTLS"
            if not os.path.exists(client_cert_path):
                return False, f"Client certificate file not found at: {client_cert_path}"
            if not os.path.exists(client_key_path):
                return False, f"Client key file not found at: {client_key_path}"
        
        feature = "verify"
        client = create_openai_client_with_custom_ca(
            config["OPENAI_API_KEY"], 
            config["OPENAI_BASE_URL"],
            custom_ca_cert_path,
            client_cert_path,
            client_key_path,
            feature
        )
        models = client.models.list()
        model_ids = [model.id for model in models.data]
        
        if config["OPENAI_MODEL"] not in model_ids:
            return False, f"Model '{config['OPENAI_MODEL']}' not found in available models: {model_ids[:5]}..."
            
        return True, "Configuration validated successfully"
    except Exception as e:
        return False, f"OpenAI API validation failed: {str(e)}"

def validate_basic_config(config: dict) -> tuple[bool, str]:
    """Validate basic configuration requirements (no network calls)."""
    issues = get_config_validation_issues(config)
    if issues:
        issue_lines = "\n".join(f"- {issue}" for issue in issues)
        return False, (
            "Configuration contains missing or invalid items:\n"
            f"{issue_lines}\n\n"
            f"Please edit the configuration file at:\n{CONFIG_FILE}"
        )

    # Check for required API key
    if not config.get("OPENAI_API_KEY"):
        return False, f"OPENAI_API_KEY is not set in configuration.\n\nPlease edit the configuration file at:\n{CONFIG_FILE}\n\nOr use the Plugin Settings editor."
    
    # Check for required model settings
    missing_models = []
    
    for model_key in MODEL_CONFIG_KEYS:
        if not config.get(model_key):
            missing_models.append(model_key)
    
    if missing_models:
        return False, f"Missing required model configuration: {', '.join(missing_models)}\n\nPlease edit the configuration file at:\n{CONFIG_FILE}"
    
    # Check file paths if provided
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    if custom_ca_cert_path and not os.path.exists(custom_ca_cert_path):
        return False, f"Custom CA certificate file not found at: {custom_ca_cert_path}"
    
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")
    if client_cert_path or client_key_path:
        if not (client_cert_path and client_key_path):
            return False, "Both CLIENT_CERT_PATH and CLIENT_KEY_PATH must be provided for mTLS"
        if not os.path.exists(client_cert_path):
            return False, f"Client certificate file not found at: {client_cert_path}"
        if not os.path.exists(client_key_path):
            return False, f"Client key file not found at: {client_key_path}"
    
    return True, "Basic configuration is valid"

def get_model_for_component(config: dict, component: str) -> str:
    """Get the appropriate model for a specific component (gatherer, annotator, ai_decomp)."""
    component_model_key = f"{component.upper()}_MODEL"
    component_model = config.get(component_model_key, "")
    
    # Fall back to OPENAI_MODEL if component-specific model is not set
    if not component_model:
        return config.get("OPENAI_MODEL", "")
    
    return component_model

def finalize_prompt(base_prompt, config = None):
    """
    Combines the base RE prompt with dynamic constraints derived from config.
    Swaps STATE placeholders with ENABLED or DISABLED.
    """
    if not config:
        config = load_config()

    def get_status(key):
        return "ENABLED" if config.get(key, True) else "DISABLED"
    
    extra_prompt = ""
    with open(PROMPT_ANNOTATOR_OPTIONS, "r", encoding="utf-8") as f:
        extra_prompt = f.read()
    
    if not extra_prompt:
        print("FAIL")
        return base_prompt

    formatted_extra = extra_prompt.format(
        desc_state=get_status('USE_DESC'),
        comm_state=get_status('USE_COMMENTS'),
        vars_state=get_status('RENAME_VARS'),
        funcs_state=get_status('RENAME_FUNCS'),
        line_state=get_status('COMMENT_EVERY_LINE')
    )

    return f"{base_prompt}\n{formatted_extra}"

def check_config_and_show_error_if_invalid(config: dict) -> bool:
    """Common function to check config and show error dialog if invalid."""
    if not os.path.exists(CONFIG_FILE):
        create_default_config()
        show_config_error()
        return False

    # Perform basic validation
    is_valid, error_msg = validate_basic_config(config)
    if not is_valid:
        ida_kernwin.warning(error_msg)
        return False

    return True