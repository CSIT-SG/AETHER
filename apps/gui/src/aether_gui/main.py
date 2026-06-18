import json

import ida_kernwin
import ida_nalt
import idaapi
from aether_rpc.gui_server import GUIRPCServer
from aether_utils.config import get_config
from aether_utils.file_id import file_id
from aether_utils.is_headless_ida import is_headless_ida
from aether_utils.logger import get_logger

from aether_gui.features.context_menu import AetherUIHooks
from aether_gui.features.font_capture import AetherFontHook, FontEnablerHook
from aether_gui.features.settings_menu import SettingsMenuHandler

ACTION_NAME = "aether:open_settings"

logger = get_logger("gui_plugin")


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Settings Menu"
    help = ""
    wanted_name = "Aether"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self._rpc_server = None
        self.hooks: dict[str, ida_kernwin.UI_Hooks]
        self._settings_handler = None

    def init(self) -> int:
        if is_headless_ida():
            logger.debug("Headless IDA detected, skipping GUI plugin initialization")
            return idaapi.PLUGIN_SKIP

        path = ida_nalt.get_input_file_path()
        if not path:
            logger.warning("No input file path available yet")
            return idaapi.PLUGIN_SKIP

        self._rpc_server = GUIRPCServer(file_id=file_id(path))

        try:
            cfg = get_config()
            logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))
        except Exception as e:
            logger.error("Failed to load config: %s", e)

        # Initialize and hook into IDA using the instance memory space
        self.hooks = {
            "ui": AetherUIHooks(),
            "font": AetherFontHook(),
            "font_enabler": FontEnablerHook(),
        }

        for name, hook in self.hooks.items():  # noqa: B007
            hook.hook()

        self._rpc_server.start()
        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        dialog = SettingsMenuHandler()
        dialog.exec()

    def term(self) -> None:
        # No global lookups. This object is guaranteed to exist right here.
        for name, hook in self.hooks.items():
            try:
                unregister = getattr(hook, "unregister", None)
                if callable(unregister):
                    unregister()
                hook.unhook()
            except Exception as e:
                logger.warning("Failed to unhook AETHER %s hook: %s", name, e)
        self.hooks.clear()

        if self._rpc_server:
            self._rpc_server.stop()
        ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_NAME)
        ida_kernwin.unregister_action(ACTION_NAME)


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()
