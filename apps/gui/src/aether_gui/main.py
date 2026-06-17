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
from aether_gui.features.settings_menu import SettingsMenuHandler

ACTION_NAME = "aether:open_settings"
from aether_gui.features.font_capture import AetherFontHook, FontEnablerHook

logger = get_logger("gui_plugin")


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Settings Menu"
    help = ""
    wanted_name = "Aether"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self._ui_hooks = None
        self._font_hook = None
        self._font_enabler = None
        self._rpc_server = None
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
        if self._ui_hooks is None:
            self._ui_hooks = AetherUIHooks()
            self._ui_hooks.hook()

        if self._font_hook is None:
            self._font_hook = AetherFontHook()
            self._font_hook.hook()

        if self._font_enabler is None:
            self._font_enabler = FontEnablerHook()
            self._font_enabler.hook()

        self._rpc_server.start()
        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        dialog = SettingsMenuHandler()
        dialog.exec()

    def term(self) -> None:
        # No global lookups. This object is guaranteed to exist right here.
        if self._ui_hooks is not None:
            try:
                self._ui_hooks.unregister()
                self._ui_hooks.unhook()
                logger.info("AETHER UI hooks cleanly unhooked.")
            except Exception as e:
                logger.warning("Failed to unhook AETHER UI hooks: %s", e)
            finally:
                self._ui_hooks = None

        if self._font_hook is not None:
            try:
                self._font_hook.unhook()
                logger.info("AETHER font hook cleanly unhooked.")
            except Exception as e:
                logger.warning("Failed to unhook AETHER font hook: %s", e)
            finally:
                self._font_hook = None

        if self._font_enabler is not None:
            try:
                self._font_enabler.unhook()
            except Exception as e:
                logger.warning("Failed to unhook font enabler: %s", e)
            finally:
                self._font_enabler = None

        if self._rpc_server:
            self._rpc_server.stop()
        ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_NAME)
        ida_kernwin.unregister_action(ACTION_NAME)


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()
