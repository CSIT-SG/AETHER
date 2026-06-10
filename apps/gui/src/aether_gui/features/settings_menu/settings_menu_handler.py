import ida_kernwin

from aether_utils.logger import get_logger
from aether_gui.features.settings_menu import config_box

logger = get_logger("settings_menu_plugin")

class SettingsMenuHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        super().__init__()
        #self