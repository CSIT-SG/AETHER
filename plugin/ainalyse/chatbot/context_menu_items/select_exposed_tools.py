from ..toolconfig import TOOL_CONFIG, TOOL_REGISTRY, save_tool_config
from ..tools import ToolSelectionDialog

class SelectExposedTools() :
    def __init__(self) : pass

    @staticmethod
    def _select_exposed_tools(CBController) :
        """Launches a dialog to configure which tools are exposed to the LLM"""
        # 1. Prepare input for the dialog (set of currently active tools)
        current_active_tools = {name for name, enabled in TOOL_CONFIG.items() if enabled}
        dlg = ToolSelectionDialog(current_active_tools, parent = CBController.parent)
        if (dlg._exec()) :
            new_enabled_tools_set = dlg.get_selected_tools
            if (current_active_tools == new_enabled_tools_set) : return 1
            # 2. Convert the set of enabled names back to the required {name: True/False} dictionary
            new_tool_config = dict()
            for tool_name in TOOL_REGISTRY.keys() :
                tool_name_str = tool_name.value
                new_tool_config[tool_name_str] = tool_name_str in new_enabled_tools_set
            # 3. Save
            if (save_tool_config(new_tool_config)) :
                # 4. Update the in-memory state of the viewer after successful save
                CBController.exposed_tools = new_enabled_tools_set
            else : print("Failed to save tool configuration. Check IDA output log.")
        return 1
    